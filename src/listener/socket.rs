// Socket primitives shared across all listener kinds: peer address,
// the accepted-stream union, bound-listener union, and the bind/adopt
// helpers used at startup, reload, and seamless upgrade.

use crate::config::{
    AddrLocation, ListenerConfig, ProxyProtocolVersion, SocketKind,
};
#[cfg(unix)]
use crate::inherit::InheritedSockets;
use crate::proxy_proto;
use anyhow::{Context as _, anyhow};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::debug;

// -- Peer address and incoming stream abstractions -----------------

/// Client address for a connection: IP+port for TCP, a sentinel for
/// Unix domain socket connections (which have no IP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerAddr {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix,
}

impl PeerAddr {
    /// IP address of the peer.  Unix sockets return loopback so that
    /// access rules with `ip "127.0.0.0/8"` match local connections.
    pub(crate) fn ip(self) -> std::net::IpAddr {
        match self {
            PeerAddr::Tcp(a) => a.ip(),
            #[cfg(unix)]
            PeerAddr::Unix => std::net::IpAddr::from([127, 0, 0, 1]),
        }
    }
}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Tcp(a) => write!(f, "{a}"),
            #[cfg(unix)]
            PeerAddr::Unix => write!(f, "[unix]"),
        }
    }
}

/// Accepted inbound stream: TCP or (on Unix) a Unix domain socket.
/// Implements tokio AsyncRead + AsyncWrite so `TokioIo::new` can wrap it.
#[cfg(unix)]
pub(crate) enum IncomingStream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

#[cfg(not(unix))]
pub(crate) enum IncomingStream {
    Tcp(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for IncomingStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            IncomingStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for IncomingStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            IncomingStream::Unix(s) => {
                std::pin::Pin::new(s).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            IncomingStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            IncomingStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Bound listener socket — one variant per `SocketKind`.  Returned by
/// `bind_socket`; consumed by the matching run_* accept loop.  All
/// non-TCP variants are unix-only at the kernel level.
#[cfg(unix)]
pub enum BoundSocket {
    Tcp(TcpListener),
    /// UDP datagram socket.  Carries either a server-side QUIC
    /// endpoint (HTTP/3) or the raw datagram-proxy loop.
    Udp(std::net::UdpSocket),
    /// AF_UNIX SOCK_STREAM listener.
    Unix(tokio::net::UnixListener),
    /// AF_UNIX SOCK_DGRAM socket — message-based, no accept loop.
    UnixDgram(tokio::net::UnixDatagram),
    /// AF_UNIX SOCK_SEQPACKET listener fd, wrapped for async accept.
    /// SEQPACKET is connection-oriented like SOCK_STREAM but preserves
    /// message boundaries on read/write.  Tokio has no first-class
    /// support; we hold the raw fd and let the datagram-proxy loop
    /// drive accept() through `tokio::io::unix::AsyncFd`.
    UnixSeqpacket(
        #[allow(dead_code)] // accept loop reads via AsyncFd; binder owns it
        tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    ),
}

#[cfg(not(unix))]
pub enum BoundSocket {
    Tcp(TcpListener),
    Udp(std::net::UdpSocket),
}

impl BoundSocket {
    /// Accept one incoming connection.  Only stream kinds (TCP and
    /// SOCK_STREAM/SEQPACKET unix) participate; message kinds are
    /// driven by the datagram-proxy loop directly.
    pub(crate) async fn accept(
        &self,
    ) -> std::io::Result<(IncomingStream, PeerAddr)> {
        match self {
            BoundSocket::Tcp(l) => {
                let (s, a) = l.accept().await?;
                Ok((IncomingStream::Tcp(s), PeerAddr::Tcp(a)))
            }
            BoundSocket::Udp(_) => Err(std::io::Error::other(
                "BoundSocket::accept called on a UDP socket",
            )),
            #[cfg(unix)]
            BoundSocket::Unix(l) => {
                let (s, _) = l.accept().await?;
                Ok((IncomingStream::Unix(s), PeerAddr::Unix))
            }
            #[cfg(unix)]
            BoundSocket::UnixDgram(_) => Err(std::io::Error::other(
                "BoundSocket::accept called on a unix-dgram socket",
            )),
            #[cfg(unix)]
            BoundSocket::UnixSeqpacket(_) => Err(std::io::Error::other(
                "BoundSocket::accept called on a unix-seqpacket \
                 socket; use the datagram-proxy loop",
            )),
        }
    }

    /// TCP local address, if the socket is TCP.  Used for
    /// stream-proxy PROXY protocol destination field.
    pub(crate) fn tcp_local_addr(&self) -> Option<SocketAddr> {
        match self {
            BoundSocket::Tcp(l) => l.local_addr().ok(),
            BoundSocket::Udp(_) => None,
            #[cfg(unix)]
            BoundSocket::Unix(_)
            | BoundSocket::UnixDgram(_)
            | BoundSocket::UnixSeqpacket(_) => None,
        }
    }
}

/// Listener-side local TCP address, inserted into request extensions
/// so the HTTP proxy handler can populate the PROXY protocol dst field.
#[derive(Clone, Copy)]
pub struct LocalAddr(pub SocketAddr);

/// Listener-side Unix socket path; inserted when the listener is bound
/// to a `unix:` address.  Used by the HTTP proxy handler to build an
/// AF_UNIX PROXY protocol v2 header instead of a fake IPv4 one.
#[derive(Clone)]
pub struct LocalUnixPath(pub std::path::PathBuf);

// -- Bind / adopt --------------------------------------------------

/// Clear `FD_CLOEXEC` on a listening socket so it survives `execve()`.
/// Required for SIGUSR2 seamless binary upgrade (#14): the new hypershunt
/// child inherits its listening sockets directly from the parent via
/// `fork()` + `execve()`, and Rust's stdlib creates sockets with
/// `SOCK_CLOEXEC` by default.  Idempotent: harmless on inherited fds
/// where the flag is already cleared.
#[cfg(unix)]
pub(crate) fn clear_cloexec<Fd: std::os::fd::AsFd>(
    fd: Fd,
) -> std::io::Result<()> {
    use nix::fcntl::{F_SETFD, FcntlArg, FdFlag, fcntl};
    let flags = fcntl(&fd, FcntlArg::F_GETFD).map_err(std::io::Error::from)?;
    let mut f = FdFlag::from_bits_truncate(flags);
    f.remove(FdFlag::FD_CLOEXEC);
    fcntl(&fd, F_SETFD(f)).map_err(std::io::Error::from)?;
    Ok(())
}

/// Bind a listener socket for the given config entry.  Called before
/// privilege drop so ports < 1024 can be bound as root.
///
/// If an inherited socket matches the bind address it is adopted from
/// the pool instead of calling bind(2).  Dispatch is by socket kind:
///   tcp           -- TcpListener
///   udp           -- std::net::UdpSocket (consumed by quinn or the
///                    datagram-proxy loop)
///   unix-stream   -- tokio::net::UnixListener
///   unix-dgram    -- tokio::net::UnixDatagram
///   unix-seqpacket -- raw SOCK_SEQPACKET fd wrapped in AsyncFd
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn bind_socket(
    cfg: &ListenerConfig,
    #[cfg(unix)] inherited: &mut InheritedSockets,
) -> anyhow::Result<BoundSocket> {
    match (cfg.bind.kind, &cfg.bind.location) {
        (SocketKind::TcpStream, AddrLocation::Inet(addr)) => {
            #[cfg(unix)]
            let inherited_fd = inherited.take_tcp(*addr);
            #[cfg(not(unix))]
            let inherited_fd: Option<std::os::unix::io::RawFd> = None;
            Ok(BoundSocket::Tcp(bind_tcp_socket(*addr, inherited_fd)?))
        }
        (SocketKind::UdpDgram, AddrLocation::Inet(addr)) => {
            Ok(BoundSocket::Udp(bind_udp_socket(
                *addr,
                #[cfg(unix)]
                inherited,
            )?))
        }
        #[cfg(unix)]
        (SocketKind::UnixStream, AddrLocation::Unix(path)) => {
            let listener = if let Some(fd) = inherited.take_unix(path) {
                use std::os::unix::io::FromRawFd;
                // SAFETY: fd is a valid, listening Unix socket from our scan.
                let std_l = unsafe {
                    std::os::unix::net::UnixListener::from_raw_fd(fd)
                };
                std_l.set_nonblocking(true)?;
                tokio::net::UnixListener::from_std(std_l)?
            } else {
                let _ = std::fs::remove_file(path);
                tokio::net::UnixListener::bind(path)?
            };
            clear_cloexec(&listener)
                .context("clearing FD_CLOEXEC on unix-stream listener")?;
            Ok(BoundSocket::Unix(listener))
        }
        #[cfg(unix)]
        (SocketKind::UnixDgram, AddrLocation::Unix(path)) => {
            // tokio::net::UnixDatagram::bind handles the socket+bind
            // dance.  Stale-file removal mirrors the unix-stream
            // path: a previous crashed run may leave the file in
            // place and prevent a fresh bind.
            let _ = std::fs::remove_file(path);
            let sock = tokio::net::UnixDatagram::bind(path)
                .with_context(|| format!(
                    "binding unix-dgram socket {}",
                    path.display()
                ))?;
            clear_cloexec(&sock)
                .context("clearing FD_CLOEXEC on unix-dgram socket")?;
            Ok(BoundSocket::UnixDgram(sock))
        }
        #[cfg(unix)]
        (SocketKind::UnixSeqpacket, AddrLocation::Unix(path)) => {
            // SEQPACKET listener.  Tokio has no native wrapper; build
            // the socket via nix, listen, and wrap the fd in AsyncFd
            // so the datagram-proxy loop can poll for readable accept.
            use nix::sys::socket::{
                AddressFamily, Backlog, SockFlag, SockType, UnixAddr,
                bind as nix_bind, listen as nix_listen,
                socket as nix_socket,
            };
            use std::os::fd::{AsRawFd as _, OwnedFd};
            let _ = std::fs::remove_file(path);
            let fd = nix_socket(
                AddressFamily::Unix,
                SockType::SeqPacket,
                SockFlag::SOCK_NONBLOCK,
                None,
            )
            .with_context(|| format!(
                "creating unix-seqpacket socket for {}",
                path.display()
            ))?;
            let addr = UnixAddr::new(path).with_context(|| {
                format!(
                    "building unix-seqpacket address for {}",
                    path.display()
                )
            })?;
            nix_bind(fd.as_raw_fd(), &addr).with_context(|| {
                format!(
                    "binding unix-seqpacket socket {}",
                    path.display()
                )
            })?;
            nix_listen(&fd, Backlog::new(128).unwrap())
                .context("listen() on unix-seqpacket socket")?;
            let owned: OwnedFd = fd;
            clear_cloexec(&owned)
                .context("clearing FD_CLOEXEC on unix-seqpacket socket")?;
            Ok(BoundSocket::UnixSeqpacket(
                tokio::io::unix::AsyncFd::new(owned)?,
            ))
        }
        (kind, loc) => Err(anyhow!(
            "bind_socket: unsupported (kind, location) combination \
             ({kind:?}, {loc:?})"
        )),
    }
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn bind_udp_socket(
    addr: SocketAddr,
    #[cfg(unix)] inherited: &mut InheritedSockets,
) -> anyhow::Result<std::net::UdpSocket> {
    #[cfg(unix)]
    let sock = if let Some(fd) = inherited.take_udp(addr) {
        use std::os::unix::io::FromRawFd;
        // SAFETY: fd is a bound UDP socket from our inherited scan.
        unsafe { std::net::UdpSocket::from_raw_fd(fd) }
    } else {
        std::net::UdpSocket::bind(addr)
            .with_context(|| format!("binding udp socket {addr}"))?
    };
    #[cfg(not(unix))]
    let sock = std::net::UdpSocket::bind(addr)
        .with_context(|| format!("binding udp socket {addr}"))?;
    sock.set_nonblocking(true)?;
    #[cfg(unix)]
    clear_cloexec(&sock).context("clearing FD_CLOEXEC on udp listener")?;
    Ok(sock)
}

/// Resolve a bind address (and optional inherited fd) into a
/// non-blocking TcpListener.
pub fn bind_tcp_socket(
    bind: SocketAddr,
    fd: Option<std::os::unix::io::RawFd>,
) -> anyhow::Result<TcpListener> {
    let std_listener = if let Some(fd) = fd {
        // Adopt an inherited socket; bind address already matches.
        // SAFETY: fd is a valid, listening TCP socket from our scan.
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            unsafe { std::net::TcpListener::from_raw_fd(fd) }
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            anyhow::bail!("fd-based listeners are only supported on Unix");
        }
    } else {
        std::net::TcpListener::bind(bind)?
    };
    std_listener.set_nonblocking(true)?;
    #[cfg(unix)]
    clear_cloexec(&std_listener)
        .context("clearing FD_CLOEXEC on tcp listener")?;
    Ok(TcpListener::from_std(std_listener)?)
}

// -- PROXY protocol header -----------------------------------------

/// Read an inbound PROXY protocol header from a freshly accepted stream
/// and return the updated peer address.
///
/// Returns `None` if the header is malformed, or if `trusted_proxies` is
/// non-empty and the TCP peer is not in the allowlist — the caller
/// should drop the connection.  Returns the original `peer_addr`
/// unchanged when the header contains an UNKNOWN or LOCAL address
/// (spec-defined no-op).
pub(crate) async fn apply_proxy_proto(
    stream: &mut IncomingStream,
    version: ProxyProtocolVersion,
    peer_addr: PeerAddr,
    trusted_proxies: &[ipnet::IpNet],
) -> Option<PeerAddr> {
    // Allowlist check runs before the header is even read so that an
    // untrusted peer cannot keep the connection open by streaming an
    // arbitrarily slow header.
    if !trusted_proxies.is_empty() {
        let ip = peer_addr.ip();
        let trusted = trusted_proxies.iter().any(|net| net.contains(&ip));
        if !trusted {
            debug!(%peer_addr, "PROXY protocol peer not in trusted-proxies");
            return None;
        }
    }
    match proxy_proto::parse_incoming(stream, version).await {
        Ok(Some((src, _dst))) => Some(PeerAddr::Tcp(src)),
        Ok(None) => Some(peer_addr),
        Err(e) => {
            debug!(%peer_addr, "PROXY protocol parse error: {e}");
            None
        }
    }
}
