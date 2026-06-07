// Raw datagram L4 proxy: forward UDP / unix-dgram packets between a
// datagram-stream listener and a datagram-stream upstream.  Per-flow
// state is keyed by `ClientKey` (source address); each flow owns one
// upstream socket plus a `last_seen` timestamp.  An eviction task
// ticks every 5 s and drops flows idle past the configured timeout.
//
// This module deliberately does NOT terminate or originate any
// encryption layer.  QUIC termination on UDP listeners belongs in
// the HTTP/3 path (`run_quic`); DTLS termination + origination are
// reserved syntax slots that aren't implemented yet.

use crate::config::{AddrLocation, ListenerConfig, SocketKind};
use crate::listener::BoundSocket;
use crate::metrics::Metrics;
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, watch};

/// Identifier for one client-side endpoint.  Raw UDP listeners use
/// the peer's `SocketAddr`; unix-dgram listeners use a stringified
/// peer path (datagram unix sockets carry a pathname only when the
/// peer is bound, which is unusual for clients -- unconnected unix
/// dgram peers identify themselves with a synthesised key
/// `"_anon-{seq}"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientKey {
    Udp(SocketAddr),
    UnixPath(std::path::PathBuf),
}

/// Default per-flow idle timeout when the config does not override.
pub const DEFAULT_FLOW_IDLE_SECS: u64 = 30;

/// Maximum single-datagram payload hypershunt will forward.  UDP+IPv4
/// theoretical max is ~65 507; we cap at 65 535 for slightly bigger
/// headroom on jumbo paths.  Buffer is per accept-loop, not per-flow.
pub const MAX_DATAGRAM_BYTES: usize = 65_535;

/// Upstream I/O endpoint for one flow.  Each variant owns whatever
/// state the upstream-side reply loop needs.
enum UpstreamSocket {
    Udp(Arc<tokio::net::UdpSocket>),
    #[cfg(unix)]
    UnixDgram(Arc<tokio::net::UnixDatagram>),
    /// AF_UNIX SOCK_SEQPACKET connected to the upstream.  Tokio has
    /// no native wrapper; we hold the connected fd in an `AsyncFd`
    /// and drive `send` / `recv` via libc through `try_io`.
    #[cfg(unix)]
    UnixSeqpacket(Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>),
}

struct Flow {
    upstream: UpstreamSocket,
    last_seen: Mutex<Instant>,
}

impl Flow {
    async fn touch(&self) {
        *self.last_seen.lock().await = Instant::now();
    }
}

/// Flow table shared between the accept loop, the reply-forwarding
/// tasks, and the eviction task.  Keyed by `ClientKey`.
pub(crate) struct FlowTable {
    flows: Mutex<HashMap<ClientKey, Arc<Flow>>>,
    idle_timeout: Duration,
}

impl FlowTable {
    fn new(idle_timeout: Duration) -> Self {
        FlowTable {
            flows: Mutex::new(HashMap::new()),
            idle_timeout,
        }
    }

    async fn evict_idle(&self, metrics: &Arc<Metrics>) {
        let now = Instant::now();
        let mut flows = self.flows.lock().await;
        let before = flows.len();
        let timeout = self.idle_timeout;
        // Two-pass: read last_seen under flow.last_seen lock without
        // holding the outer lock during eviction would race, so we
        // build a drop list while holding the outer lock and look up
        // each flow's last_seen under its inner lock.
        let mut to_drop = Vec::new();
        for (key, flow) in flows.iter() {
            let last = *flow.last_seen.lock().await;
            if now.duration_since(last) >= timeout {
                to_drop.push(key.clone());
            }
        }
        for key in &to_drop {
            flows.remove(key);
        }
        let after = flows.len();
        if before != after {
            metrics
                .datagram_flows_active
                .store(after as u64, std::sync::atomic::Ordering::Relaxed);
            metrics
                .datagram_flow_evict_total
                .fetch_add(
                    (before - after) as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
        }
    }
}

/// Spawn the eviction task for one flow table.  Returns the
/// JoinHandle so the listener cleanup path can abort it when the
/// listener is removed at reload time.
fn spawn_evictor(
    table: Arc<FlowTable>,
    metrics: Arc<Metrics>,
    mut stop: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    crate::task::spawn_supervised("datagram.evictor", async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = tick.tick() => table.evict_idle(&metrics).await,
                _ = stop.changed() => {
                    if *stop.borrow() { return; }
                }
            }
        }
    })
}

/// Run a raw datagram proxy: no QUIC termination on the listener
/// side.  Supports UDP/unix-dgram listeners with UDP/unix-dgram or
/// QUIC-client upstreams.  `_router` is currently unused; reserved
/// for future per-flow policy evaluation.
pub async fn run_dgram_proxy(
    cfg: ListenerConfig,
    socket: BoundSocket,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
    mut stop_accept: watch::Receiver<bool>,
) -> Result<()> {
    let name = cfg.local_name();
    let proxy = cfg
        .proxy
        .as_ref()
        .ok_or_else(|| anyhow!("dgram-proxy requires cfg.proxy"))?
        .clone();
    let idle = Duration::from_secs(
        proxy.flow_idle_timeout_secs.unwrap_or(DEFAULT_FLOW_IDLE_SECS),
    );
    let table = Arc::new(FlowTable::new(idle));
    let _evictor =
        spawn_evictor(table.clone(), metrics.clone(), stop_accept.clone());

    // The accept-side primitive depends on the listener's socket
    // kind.  Each branch shares the same per-packet flow lookup +
    // forward logic but reads/writes through its own primitive.
    match (cfg.bind.kind, socket) {
        (SocketKind::UdpDgram, BoundSocket::Udp(std_sock)) => {
            let listener = tokio::net::UdpSocket::from_std(std_sock)
                .context("wrapping inbound UDP socket")?;
            let listener = Arc::new(listener);
            tracing::info!(
                bind = %name,
                upstream = %proxy.upstream,
                "listening (udp-dgram proxy)"
            );
            let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
            loop {
                tokio::select! {
                    res = listener.recv_from(&mut buf) => {
                        let (n, peer) = match res {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(
                                    bind = %name,
                                    "udp recv_from: {e}"
                                );
                                continue;
                            }
                        };
                        forward_udp_in(
                            ClientKey::Udp(peer),
                            &buf[..n],
                            &table,
                            &proxy,
                            &listener,
                            &metrics,
                        )
                        .await;
                    }
                    _ = shutdown.changed() => return Ok(()),
                    _ = stop_accept.changed() => {
                        if *stop_accept.borrow() { return Ok(()); }
                    }
                }
            }
        }
        #[cfg(unix)]
        (SocketKind::UnixDgram, BoundSocket::UnixDgram(sock)) => {
            let sock = Arc::new(sock);
            tracing::info!(
                bind = %name,
                upstream = %proxy.upstream,
                "listening (unix-dgram proxy)"
            );
            let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
            loop {
                tokio::select! {
                    res = sock.recv_from(&mut buf) => {
                        let (n, peer) = match res {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(
                                    bind = %name,
                                    "unix-dgram recv_from: {e}"
                                );
                                continue;
                            }
                        };
                        // Unix-dgram peers may be anonymous (no
                        // bound path).  We synthesise a deterministic
                        // key per source so the flow table can
                        // demultiplex; replies will be lost for
                        // anonymous peers since they have no return
                        // address (a known limitation).
                        let key = match peer.as_pathname() {
                            Some(p) => {
                                ClientKey::UnixPath(p.to_path_buf())
                            }
                            None => continue,
                        };
                        forward_unix_in(
                            key,
                            &buf[..n],
                            &table,
                            &proxy,
                            &sock,
                            &metrics,
                        )
                        .await;
                    }
                    _ = shutdown.changed() => return Ok(()),
                    _ = stop_accept.changed() => {
                        if *stop_accept.borrow() { return Ok(()); }
                    }
                }
            }
        }
        #[cfg(unix)]
        (SocketKind::UnixSeqpacket, BoundSocket::UnixSeqpacket(listener)) => {
            // SEQPACKET is connection-oriented: accept yields a new
            // connected fd per client, and reads/writes on that fd
            // preserve message boundaries.  This doesn't fit the
            // flow-table model -- each accepted connection has its
            // own upstream socket and lives until either side closes.
            // We spawn a per-connection forwarder, mirroring the
            // byte-stream proxy's shape but with message-preserving
            // I/O.
            tracing::info!(
                bind = %name,
                upstream = %proxy.upstream,
                "listening (unix-seqpacket proxy)"
            );
            let listener = Arc::new(listener);
            loop {
                tokio::select! {
                    res = seqpacket_accept(&listener) => {
                        let client_fd = match res {
                            Ok(fd) => fd,
                            Err(e) => {
                                tracing::warn!(
                                    bind = %name,
                                    "unix-seqpacket accept: {e}"
                                );
                                continue;
                            }
                        };
                        let proxy = proxy.clone();
                        let metrics = metrics.clone();
                        crate::task::spawn_supervised(
                            "datagram.seqpacket-conn",
                            seqpacket_per_conn(
                                client_fd, proxy, metrics,
                            ),
                        );
                    }
                    _ = shutdown.changed() => return Ok(()),
                    _ = stop_accept.changed() => {
                        if *stop_accept.borrow() { return Ok(()); }
                    }
                }
            }
        }
        (k, _) => Err(anyhow!(
            "run_dgram_proxy: unsupported listener kind {k:?}"
        )),
    }
}

/// Per-accepted-connection forwarder for a SOCK_SEQPACKET listener.
/// Wraps the client fd in an AsyncFd, opens one upstream socket,
/// and runs two halves -- client→upstream and upstream→client --
/// until either direction closes or errors.
#[cfg(unix)]
async fn seqpacket_per_conn(
    client_fd: std::os::fd::OwnedFd,
    proxy: crate::config::ProxyConfig,
    metrics: Arc<Metrics>,
) {
    let client = match tokio::io::unix::AsyncFd::new(client_fd) {
        Ok(f) => Arc::new(f),
        Err(e) => {
            tracing::warn!(
                "seqpacket-conn: registering client fd: {e}"
            );
            return;
        }
    };
    let upstream = match build_upstream(&proxy).await {
        Ok(u) => Arc::new(u),
        Err(e) => {
            tracing::warn!(
                upstream = %proxy.upstream,
                "seqpacket-conn: building upstream: {e:#}"
            );
            return;
        }
    };
    metrics
        .datagram_flow_create_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    metrics
        .datagram_flows_active
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let client_to_up = {
        let client = client.clone();
        let upstream = upstream.clone();
        let metrics = metrics.clone();
        async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
            loop {
                match seqpacket_recv(&client, &mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        metrics.datagrams_in_total.fetch_add(
                            1, std::sync::atomic::Ordering::Relaxed,
                        );
                        metrics.bytes_in_total.fetch_add(
                            n as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        send_to_upstream(&upstream, &buf[..n], &metrics)
                            .await;
                    }
                    Err(_) => return,
                }
            }
        }
    };
    let up_to_client = {
        let metrics = metrics.clone();
        async move {
        let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
        loop {
            let n = match upstream.as_ref() {
                UpstreamSocket::UnixSeqpacket(fd) => {
                    match seqpacket_recv(fd, &mut buf).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(_) => return,
                    }
                }
                UpstreamSocket::Udp(s) => match s.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                },
                UpstreamSocket::UnixDgram(s) => match s.recv(&mut buf).await
                {
                    Ok(n) => n,
                    Err(_) => return,
                },
            };
            if seqpacket_send(&client, &buf[..n]).await.is_err() {
                return;
            }
            metrics
                .bytes_out_total
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        }
    };
    // Run both halves until either ends; cancellation of one cancels
    // the other via the join's drop.
    tokio::select! {
        _ = client_to_up => {}
        _ = up_to_client => {}
    }
    metrics
        .datagram_flows_active
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
}

/// Handle one inbound UDP datagram: get-or-create the flow, send
/// to the upstream, spawn the reply task on first use.
async fn forward_udp_in(
    key: ClientKey,
    payload: &[u8],
    table: &Arc<FlowTable>,
    proxy: &crate::config::ProxyConfig,
    listener: &Arc<tokio::net::UdpSocket>,
    metrics: &Arc<Metrics>,
) {
    let (flow, fresh) =
        get_or_create_flow(key.clone(), table, proxy, metrics).await;
    let flow = match flow {
        Some(f) => f,
        None => return,
    };
    flow.touch().await;
    metrics
        .datagrams_in_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    metrics
        .bytes_in_total
        .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
    send_to_upstream(&flow.upstream, payload, metrics).await;
    if fresh {
        spawn_reply_task(key, flow, table.clone(), listener.clone(), metrics.clone());
    }
}

#[cfg(unix)]
async fn forward_unix_in(
    key: ClientKey,
    payload: &[u8],
    table: &Arc<FlowTable>,
    proxy: &crate::config::ProxyConfig,
    listener: &Arc<tokio::net::UnixDatagram>,
    metrics: &Arc<Metrics>,
) {
    let (flow, fresh) =
        get_or_create_flow(key.clone(), table, proxy, metrics).await;
    let flow = match flow {
        Some(f) => f,
        None => return,
    };
    flow.touch().await;
    metrics
        .datagrams_in_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    metrics
        .bytes_in_total
        .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
    send_to_upstream(&flow.upstream, payload, metrics).await;
    if fresh {
        spawn_unix_reply_task(
            key,
            flow,
            table.clone(),
            listener.clone(),
            metrics.clone(),
        );
    }
}

/// Get an existing flow or create one by connecting/binding the
/// upstream socket lazily.  Returns `(flow, fresh)` where `fresh`
/// signals that the caller should spawn a reply-pumping task.
async fn get_or_create_flow(
    key: ClientKey,
    table: &Arc<FlowTable>,
    proxy: &crate::config::ProxyConfig,
    metrics: &Arc<Metrics>,
) -> (Option<Arc<Flow>>, bool) {
    {
        let flows = table.flows.lock().await;
        if let Some(f) = flows.get(&key) {
            return (Some(f.clone()), false);
        }
    }
    let upstream = match build_upstream(proxy).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                upstream = %proxy.upstream,
                "failed to open upstream: {e:#}"
            );
            return (None, false);
        }
    };
    let flow = Arc::new(Flow {
        upstream,
        last_seen: Mutex::new(Instant::now()),
    });
    let mut flows = table.flows.lock().await;
    // Race: another inbound packet may have created the flow first.
    if let Some(existing) = flows.get(&key) {
        return (Some(existing.clone()), false);
    }
    flows.insert(key, flow.clone());
    metrics
        .datagram_flows_active
        .store(flows.len() as u64, std::sync::atomic::Ordering::Relaxed);
    metrics
        .datagram_flow_create_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    (Some(flow), true)
}

async fn build_upstream(
    proxy: &crate::config::ProxyConfig,
) -> Result<UpstreamSocket> {
    match (proxy.upstream.kind, &proxy.upstream.location) {
        (SocketKind::UdpDgram, AddrLocation::Inet(addr)) => {
            // Plain UDP: pick an ephemeral local port and `connect`
            // the socket to the upstream so subsequent send/recv use
            // the bound peer without re-specifying the destination.
            let bind_addr = unspecified_for(addr);
            let sock = tokio::net::UdpSocket::bind(bind_addr)
                .await
                .with_context(|| {
                    format!("binding ephemeral udp socket for {addr}")
                })?;
            sock.connect(*addr).await.with_context(|| {
                format!("connecting udp upstream {addr}")
            })?;
            Ok(UpstreamSocket::Udp(Arc::new(sock)))
        }
        #[cfg(unix)]
        (SocketKind::UnixDgram, AddrLocation::Unix(path)) => {
            // Bind the upstream socket to a pathname-style address so
            // the backend's `recv_from` returns a peer pathname (and
            // can therefore reply).  Anonymous / abstract sockets
            // would leave the backend with no return address.
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let local = std::env::temp_dir().join(format!(
                "hypershunt-dgram-{}-{n}.sock",
                std::process::id()
            ));
            // Remove any stale leftover from a previous run that crashed
            // before delete could fire.
            let _ = std::fs::remove_file(&local);
            let sock =
                tokio::net::UnixDatagram::bind(&local).with_context(
                    || {
                        format!(
                            "binding ephemeral unix-dgram socket {}",
                            local.display()
                        )
                    },
                )?;
            sock.connect(path).with_context(|| {
                format!(
                    "connecting unix-dgram upstream {}",
                    path.display()
                )
            })?;
            Ok(UpstreamSocket::UnixDgram(Arc::new(sock)))
        }
        #[cfg(unix)]
        (SocketKind::UnixSeqpacket, AddrLocation::Unix(path)) => {
            // SOCK_SEQPACKET is connection-oriented; one connect per
            // upstream socket.  Build a blocking fd, connect, then
            // flip non-blocking so the AsyncFd can drive send/recv.
            use nix::fcntl::{FcntlArg, OFlag, fcntl};
            use nix::sys::socket::{
                AddressFamily, SockFlag, SockType, UnixAddr,
                connect as nix_connect, socket as nix_socket,
            };
            use std::os::fd::{AsRawFd as _, OwnedFd};
            let fd = nix_socket(
                AddressFamily::Unix,
                SockType::SeqPacket,
                SockFlag::empty(),
                None,
            )
            .context("creating unix-seqpacket upstream socket")?;
            let addr = UnixAddr::new(path).with_context(|| {
                format!(
                    "building unix-seqpacket address for {}",
                    path.display()
                )
            })?;
            nix_connect(fd.as_raw_fd(), &addr).with_context(|| {
                format!(
                    "connecting unix-seqpacket upstream {}",
                    path.display()
                )
            })?;
            // Flip non-blocking so AsyncFd::readable/writable work.
            fcntl(&fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
                .context("setting O_NONBLOCK on unix-seqpacket upstream")?;
            let owned: OwnedFd = fd;
            let async_fd = tokio::io::unix::AsyncFd::new(owned)
                .context("registering unix-seqpacket upstream with reactor")?;
            Ok(UpstreamSocket::UnixSeqpacket(Arc::new(async_fd)))
        }
        (kind, _) => Err(anyhow!(
            "unsupported upstream kind {kind:?}"
        )),
    }
}

/// Send one message on a connected SOCK_SEQPACKET fd.  Returns the
/// number of bytes written (which always equals `buf.len()` for
/// SEQPACKET since it preserves boundaries; a short write would be
/// a kernel bug).
#[cfg(unix)]
async fn seqpacket_send(
    fd: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    buf: &[u8],
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd as _;
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| {
            let r = unsafe {
                libc::send(
                    inner.as_raw_fd(),
                    buf.as_ptr() as *const _,
                    buf.len(),
                    0,
                )
            };
            if r < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(r as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// Read one message from a connected SOCK_SEQPACKET fd.  The kernel
/// truncates messages larger than `buf.len()`; we size buffers to
/// `MAX_DATAGRAM_BYTES` so this is fine in practice.
#[cfg(unix)]
async fn seqpacket_recv(
    fd: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd as _;
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| {
            let r = unsafe {
                libc::recv(
                    inner.as_raw_fd(),
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    0,
                )
            };
            if r < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(r as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// Accept one incoming SOCK_SEQPACKET connection from a listening
/// fd.  Returns the accepted fd, ready to be wrapped in an AsyncFd.
#[cfg(unix)]
async fn seqpacket_accept(
    fd: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| {
            let r = unsafe {
                libc::accept4(
                    inner.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };
            if r < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                // SAFETY: r is a fresh fd from accept4, owned by us.
                Ok(unsafe { OwnedFd::from_raw_fd(r) })
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// Return the wildcard local address in the same family as `addr`,
/// so the ephemeral upstream socket binds to v4 for v4 peers and v6
/// for v6 peers.
fn unspecified_for(addr: &SocketAddr) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

async fn send_to_upstream(
    up: &UpstreamSocket,
    payload: &[u8],
    metrics: &Arc<Metrics>,
) {
    match up {
        UpstreamSocket::Udp(s) => {
            if let Err(e) = s.send(payload).await {
                tracing::warn!("udp send: {e}");
            }
        }
        #[cfg(unix)]
        UpstreamSocket::UnixDgram(s) => {
            if let Err(e) = s.send(payload).await {
                tracing::warn!("unix-dgram send: {e}");
            }
        }
        #[cfg(unix)]
        UpstreamSocket::UnixSeqpacket(fd) => {
            if let Err(e) = seqpacket_send(fd, payload).await {
                tracing::warn!(
                    "unix-seqpacket send: {e}"
                );
            }
        }
    }
    metrics
        .datagrams_out_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    metrics
        .bytes_out_total
        .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
}

/// Per-flow reply loop for a UDP-listener flow.  Reads from the
/// upstream socket (or QUIC Connection) and writes back to the
/// originating client.
fn spawn_reply_task(
    key: ClientKey,
    flow: Arc<Flow>,
    table: Arc<FlowTable>,
    listener: Arc<tokio::net::UdpSocket>,
    metrics: Arc<Metrics>,
) {
    let peer = match key {
        ClientKey::Udp(p) => p,
        _ => return,
    };
    crate::task::spawn_supervised("datagram.reply-udp", async move {
        let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
        loop {
            let n = match &flow.upstream {
                UpstreamSocket::Udp(s) => match s.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(
                            "upstream recv: {e}"
                        );
                        break;
                    }
                },
                #[cfg(unix)]
                UpstreamSocket::UnixDgram(s) => match s.recv(&mut buf).await
                {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(
                            "upstream recv: {e}"
                        );
                        break;
                    }
                },
                #[cfg(unix)]
                UpstreamSocket::UnixSeqpacket(fd) => {
                    match seqpacket_recv(fd, &mut buf).await {
                        Ok(0) => break, // peer closed
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(
                                "seqpacket recv: {e}"
                            );
                            break;
                        }
                    }
                }
            };
            if let Err(e) = listener.send_to(&buf[..n], peer).await {
                tracing::warn!(
                    "send_to client {peer}: {e}"
                );
                break;
            }
            flow.touch().await;
            metrics
                .bytes_out_total
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        // Reply loop ended: drop the flow so a follow-up datagram
        // re-establishes the upstream cleanly.
        let mut flows = table.flows.lock().await;
        flows.remove(&ClientKey::Udp(peer));
        metrics
            .datagram_flows_active
            .store(flows.len() as u64, std::sync::atomic::Ordering::Relaxed);
    });
}

#[cfg(unix)]
fn spawn_unix_reply_task(
    key: ClientKey,
    flow: Arc<Flow>,
    table: Arc<FlowTable>,
    listener: Arc<tokio::net::UnixDatagram>,
    metrics: Arc<Metrics>,
) {
    let peer_path = match &key {
        ClientKey::UnixPath(p) => p.clone(),
        _ => return,
    };
    crate::task::spawn_supervised("datagram.reply-unix", async move {
        let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
        loop {
            let n = match &flow.upstream {
                #[cfg(unix)]
                UpstreamSocket::UnixDgram(s) => match s.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(
                            "upstream recv: {e}"
                        );
                        break;
                    }
                },
                UpstreamSocket::Udp(s) => match s.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(
                            "upstream recv: {e}"
                        );
                        break;
                    }
                },
                UpstreamSocket::UnixSeqpacket(fd) => {
                    match seqpacket_recv(fd, &mut buf).await {
                        Ok(0) => break, // peer closed
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(
                                "seqpacket recv: {e}"
                            );
                            break;
                        }
                    }
                }
            };
            if let Err(e) = listener.send_to(&buf[..n], &peer_path).await {
                tracing::warn!(
                    "send_to client {}: {e}",
                    peer_path.display()
                );
                break;
            }
            flow.touch().await;
            metrics
                .bytes_out_total
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        let mut flows = table.flows.lock().await;
        flows.remove(&ClientKey::UnixPath(peer_path));
        metrics
            .datagram_flows_active
            .store(flows.len() as u64, std::sync::atomic::Ordering::Relaxed);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn flow_table_evicts_idle_entries() {
        let table = Arc::new(FlowTable::new(Duration::from_millis(50)));
        // Insert a flow with stale last_seen.
        let key = ClientKey::Udp("127.0.0.1:1".parse().unwrap());
        let endpoint =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        table.flows.lock().await.insert(
            key.clone(),
            Arc::new(Flow {
                upstream: UpstreamSocket::Udp(Arc::new(endpoint)),
                last_seen: Mutex::new(
                    Instant::now() - Duration::from_secs(5),
                ),
            }),
        );
        let metrics = Arc::new(Metrics::new());
        table.evict_idle(&metrics).await;
        assert!(
            table.flows.lock().await.is_empty(),
            "stale flow should be evicted"
        );
    }

    #[tokio::test]
    async fn flow_table_keeps_fresh_entries() {
        let table = Arc::new(FlowTable::new(Duration::from_secs(60)));
        let key = ClientKey::Udp("127.0.0.1:1".parse().unwrap());
        let endpoint =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        table.flows.lock().await.insert(
            key.clone(),
            Arc::new(Flow {
                upstream: UpstreamSocket::Udp(Arc::new(endpoint)),
                last_seen: Mutex::new(Instant::now()),
            }),
        );
        let metrics = Arc::new(Metrics::new());
        table.evict_idle(&metrics).await;
        assert_eq!(table.flows.lock().await.len(), 1);
    }

    /// End-to-end UDP-to-UDP proxy: stand up an echo backend, a
    /// listener-side BoundSocket, drive a packet through, observe
    /// the echo come back to the client.
    #[tokio::test]
    async fn udp_proxy_round_trip() {
        use crate::config::{
            BoundAddr, ListenerConfig, ProxyConfig, Timeouts,
        };

        // 1. UDP echo backend.
        let backend =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = backend.recv_from(&mut buf).await.unwrap();
                backend.send_to(&buf[..n], peer).await.unwrap();
            }
        });

        // 2. Pre-bind the listener socket so we know its address.
        let listener_std =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        listener_std.set_nonblocking(true).unwrap();
        let listener_addr = listener_std.local_addr().unwrap();

        // 3. Build the listener config and run the proxy task.
        let cfg = ListenerConfig {
            bind: BoundAddr::parse(&format!("udp://{listener_addr}"))
                .unwrap(),
            tls: None,
            quic: None,
            dtls: None,
            proxy: Some(ProxyConfig {
                upstream: BoundAddr::parse(&format!(
                    "udp://{backend_addr}"
                ))
                .unwrap(),
                upstream_tls: None,
                upstream_dtls: None,
                proxy_protocol: None,
                policy: None,
                flow_idle_timeout_secs: None,
            }),
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            default_vhost: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        let metrics = Arc::new(Metrics::new());
        let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let (_st_tx, st_rx) = tokio::sync::watch::channel(false);
        let _task = tokio::spawn(run_dgram_proxy(
            cfg,
            BoundSocket::Udp(listener_std),
            metrics.clone(),
            sd_rx,
            st_rx,
        ));

        // 4. Drive a client packet through the proxy.
        let client =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(listener_addr).await.unwrap();
        client.send(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(
            Duration::from_secs(2),
            client.recv(&mut buf),
        )
        .await
        .expect("echo did not arrive")
        .unwrap();
        assert_eq!(&buf[..n], b"hello");
        // Flow should be active.
        let active = metrics
            .datagram_flows_active
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(active, 1);
    }

    /// End-to-end unix-dgram → unix-dgram proxy: socat is not needed
    /// since tokio::net::UnixDatagram covers both sides natively.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_dgram_proxy_round_trip() {
        use crate::config::{
            BoundAddr, ListenerConfig, ProxyConfig, Timeouts,
        };

        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("listen.sock");
        let backend_path = dir.path().join("backend.sock");
        let client_path = dir.path().join("client.sock");

        // 1. Echo backend: read+write back to the sender.
        let backend =
            tokio::net::UnixDatagram::bind(&backend_path).unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = backend.recv_from(&mut buf).await.unwrap();
                if let Some(p) = peer.as_pathname() {
                    backend.send_to(&buf[..n], p).await.unwrap();
                }
            }
        });

        // 2. Bind the listener socket up front so we own the fd.
        let listener_sock =
            tokio::net::UnixDatagram::bind(&listen_path).unwrap();

        // 3. Listener config + spawn.
        let cfg = ListenerConfig {
            bind: BoundAddr::parse(&format!(
                "unix-dgram:{}",
                listen_path.display()
            ))
            .unwrap(),
            tls: None,
            quic: None,
            dtls: None,
            proxy: Some(ProxyConfig {
                upstream: BoundAddr::parse(&format!(
                    "unix-dgram:{}",
                    backend_path.display()
                ))
                .unwrap(),
                upstream_tls: None,
                upstream_dtls: None,
                proxy_protocol: None,
                policy: None,
                flow_idle_timeout_secs: None,
            }),
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            default_vhost: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        let metrics = Arc::new(Metrics::new());
        let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let (_st_tx, st_rx) = tokio::sync::watch::channel(false);
        let _task = tokio::spawn(run_dgram_proxy(
            cfg,
            BoundSocket::UnixDgram(listener_sock),
            metrics.clone(),
            sd_rx,
            st_rx,
        ));

        // 4. Client side: bind a pathname so the reply has a return
        // address, then send + receive.
        let client =
            tokio::net::UnixDatagram::bind(&client_path).unwrap();
        client.connect(&listen_path).unwrap();
        client.send(b"ping").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(
            Duration::from_secs(2),
            client.recv(&mut buf),
        )
        .await
        .expect("echo did not arrive")
        .unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    /// UDP listener → unix-dgram upstream → reply back to UDP client.
    /// Pins gap fix #1: the reply task now drains the unix-dgram
    /// upstream socket and forwards each datagram back through the
    /// UDP listener to the originating peer.
    #[cfg(unix)]
    #[tokio::test]
    async fn udp_to_unix_dgram_round_trip() {
        use crate::config::{
            BoundAddr, ListenerConfig, ProxyConfig, Timeouts,
        };

        let dir = tempfile::tempdir().unwrap();
        let backend_path = dir.path().join("backend.sock");

        // Echo backend on a unix-dgram socket.
        let backend =
            tokio::net::UnixDatagram::bind(&backend_path).unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = backend.recv_from(&mut buf).await.unwrap();
                if let Some(p) = peer.as_pathname() {
                    backend.send_to(&buf[..n], p).await.unwrap();
                }
            }
        });

        let listener_std =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        listener_std.set_nonblocking(true).unwrap();
        let listener_addr = listener_std.local_addr().unwrap();

        let cfg = ListenerConfig {
            bind: BoundAddr::parse(&format!("udp://{listener_addr}"))
                .unwrap(),
            tls: None,
            quic: None,
            dtls: None,
            proxy: Some(ProxyConfig {
                upstream: BoundAddr::parse(&format!(
                    "unix-dgram:{}",
                    backend_path.display()
                ))
                .unwrap(),
                upstream_tls: None,
                upstream_dtls: None,
                proxy_protocol: None,
                policy: None,
                flow_idle_timeout_secs: None,
            }),
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            default_vhost: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        let metrics = Arc::new(Metrics::new());
        let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let (_st_tx, st_rx) = tokio::sync::watch::channel(false);
        let _task = tokio::spawn(run_dgram_proxy(
            cfg,
            BoundSocket::Udp(listener_std),
            metrics,
            sd_rx,
            st_rx,
        ));

        let client =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(listener_addr).await.unwrap();
        client.send(b"cross-family").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(
            Duration::from_secs(2),
            client.recv(&mut buf),
        )
        .await
        .expect("echo did not arrive")
        .unwrap();
        assert_eq!(&buf[..n], b"cross-family");
    }

    /// SEQPACKET listener → SEQPACKET upstream.  Pins gap fixes #2
    /// (listener accept loop) and #3 (upstream).  Uses nix directly
    /// for the backend + client since tokio has no SEQPACKET wrapper.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unix_seqpacket_round_trip() {
        use crate::config::{
            BoundAddr, ListenerConfig, ProxyConfig, Timeouts,
        };
        use nix::sys::socket::{
            AddressFamily, Backlog, SockFlag, SockType, UnixAddr,
            accept as nix_accept, bind as nix_bind,
            connect as nix_connect, listen as nix_listen,
            socket as nix_socket,
        };
        use std::os::fd::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("listen.sock");
        let backend_path = dir.path().join("backend.sock");

        // Echo SEQPACKET backend, plain blocking I/O on a thread.
        let backend_fd = nix_socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        nix_bind(
            backend_fd.as_raw_fd(),
            &UnixAddr::new(&backend_path).unwrap(),
        )
        .unwrap();
        nix_listen(&backend_fd, Backlog::new(8).unwrap()).unwrap();
        std::thread::spawn(move || {
            loop {
                let conn_fd =
                    match nix_accept(backend_fd.as_raw_fd()) {
                        Ok(fd) => fd,
                        Err(_) => return,
                    };
                let mut buf = [0u8; 1500];
                loop {
                    let n = unsafe {
                        libc::recv(
                            conn_fd,
                            buf.as_mut_ptr() as *mut _,
                            buf.len(),
                            0,
                        )
                    };
                    if n <= 0 {
                        unsafe { libc::close(conn_fd) };
                        break;
                    }
                    let _ = unsafe {
                        libc::send(
                            conn_fd,
                            buf.as_ptr() as *const _,
                            n as usize,
                            0,
                        )
                    };
                }
            }
        });

        // Pre-bind the SEQPACKET listener fd via the production
        // binder so we exercise the same path the parser/main use.
        let cfg = ListenerConfig {
            bind: BoundAddr::parse(&format!(
                "unix-seqpacket:{}",
                listen_path.display()
            ))
            .unwrap(),
            tls: None,
            quic: None,
            dtls: None,
            proxy: Some(ProxyConfig {
                upstream: BoundAddr::parse(&format!(
                    "unix-seqpacket:{}",
                    backend_path.display()
                ))
                .unwrap(),
                upstream_tls: None,
                upstream_dtls: None,
                proxy_protocol: None,
                policy: None,
                flow_idle_timeout_secs: None,
            }),
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            default_vhost: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        let mut inherited =
            crate::inherit::InheritedSockets::empty();
        let bound =
            crate::listener::bind_socket(&cfg, &mut inherited).unwrap();
        let metrics = Arc::new(Metrics::new());
        let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let (_st_tx, st_rx) = tokio::sync::watch::channel(false);
        let _task = tokio::spawn(run_dgram_proxy(
            cfg, bound, metrics, sd_rx, st_rx,
        ));
        // Give the accept loop a moment to register before connecting.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Client: SEQPACKET connect, send, recv.
        let client_fd = nix_socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        nix_connect(
            client_fd.as_raw_fd(),
            &UnixAddr::new(&listen_path).unwrap(),
        )
        .unwrap();
        let payload = b"seqpacket-ok";
        let sent = unsafe {
            libc::send(
                client_fd.as_raw_fd(),
                payload.as_ptr() as *const _,
                payload.len(),
                0,
            )
        };
        assert_eq!(sent as usize, payload.len());
        let mut buf = [0u8; 64];
        // Bound the blocking recv with a small alarm via a thread
        // (tokio doesn't drive this fd).  In practice the proxy
        // round-trips well under a second.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let n = unsafe {
                libc::recv(
                    client_fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    0,
                )
            };
            let _ = tx.send((n, buf));
        });
        let (n, buf) =
            rx.recv_timeout(Duration::from_secs(2)).expect("recv");
        assert!(n > 0, "client recv failed: {n}");
        assert_eq!(&buf[..n as usize], b"seqpacket-ok");
    }
}
