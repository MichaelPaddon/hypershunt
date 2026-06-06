// Transparent socket inheritance for seamless process upgrades.
//
// At startup, hypershunt scans all open file descriptors and collects those
// that are listening sockets (TCP or Unix domain).  bind_socket() checks
// this pool before calling bind(2): if an inherited fd matches the
// configured address it is adopted directly, preserving open connections
// across the upgrade.  Unmatched inherited fds remain open, so a
// subsequent bind() on the same address fails with EADDRINUSE — the
// intended loud failure when config and environment diverge.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub struct InheritedSockets {
    tcp: HashMap<SocketAddr, RawFd>,
    udp: HashMap<SocketAddr, RawFd>,
    unix: HashMap<PathBuf, RawFd>,
}

impl InheritedSockets {
    /// Empty pool -- no inherited sockets.  Used by tests and any
    /// caller that wants to skip the fd scan.
    #[allow(dead_code)]
    pub fn empty() -> Self {
        InheritedSockets {
            tcp: HashMap::new(),
            udp: HashMap::new(),
            unix: HashMap::new(),
        }
    }

    /// Scan all open fds and collect listening sockets into the pool.
    /// Never fails: errors on individual fds are silently skipped.
    pub fn scan() -> Self {
        let mut tcp = HashMap::new();
        let mut udp = HashMap::new();
        let mut unix = HashMap::new();

        for fd in open_fds() {
            classify_fd(fd, &mut tcp, &mut udp, &mut unix);
        }

        if !tcp.is_empty() || !udp.is_empty() || !unix.is_empty() {
            tracing::debug!(
                tcp = tcp.len(),
                udp = udp.len(),
                unix = unix.len(),
                "inherited sockets found"
            );
        }
        InheritedSockets { tcp, udp, unix }
    }

    /// Take the TCP fd bound to `addr`, if one was inherited.
    /// Removing it prevents the same fd from being claimed twice.
    pub fn take_tcp(&mut self, addr: SocketAddr) -> Option<RawFd> {
        self.tcp.remove(&addr)
    }

    /// Take the UDP (QUIC) fd bound to `addr`, if one was inherited.
    /// UDP has no listening state -- SOCK_DGRAM with a bound local
    /// address is enough to be recognised by `classify_fd`.
    pub fn take_udp(&mut self, addr: SocketAddr) -> Option<RawFd> {
        self.udp.remove(&addr)
    }

    /// Take the Unix fd bound to `path`, if one was inherited.
    pub fn take_unix(&mut self, path: &std::path::Path) -> Option<RawFd> {
        self.unix.remove(path)
    }

    /// Test-only constructor that lets a test pre-populate the UDP map
    /// without going through the `/proc/self/fd` scan.  Used by the
    /// socket-activation end-to-end test so we can simulate systemd
    /// handing us a SOCK_DGRAM fd at startup.
    #[cfg(test)]
    pub(crate) fn from_udp_for_test(
        entries: HashMap<SocketAddr, RawFd>,
    ) -> Self {
        InheritedSockets {
            tcp: HashMap::new(),
            udp: entries,
            unix: HashMap::new(),
        }
    }

    /// Close every inherited socket that wasn't claimed by a listener
    /// during startup.  Critical during a SIGUSR2 binary upgrade where
    /// the new config drops one of the parent's listeners: without
    /// this, the child holds the inherited fd open but never calls
    /// accept() on it, so new client connections to the dropped port
    /// hang in the kernel backlog instead of getting a fast RST.
    ///
    /// Each unclaimed fd is logged at INFO ("dropped by new config")
    /// or WARN ("address mismatch") -- the former is expected when an
    /// operator intentionally removes a listener; the latter signals
    /// a likely operator mistake we can't distinguish in this layer,
    /// so we log loudly either way.
    pub fn close_unclaimed(self) {
        use std::os::fd::FromRawFd;
        for (addr, fd) in self.tcp {
            tracing::info!(
                fd, %addr,
                "closing inherited TCP socket not claimed by any listener"
            );
            // SAFETY: the fd was originally adopted by the inherit
            // scan; nothing else in the new process owns it.  Wrap
            // in OwnedFd so its Drop closes the kernel fd.
            let _ = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        }
        for (path, fd) in self.unix {
            tracing::info!(
                fd, path = %path.display(),
                "closing inherited Unix socket not claimed by any listener"
            );
            let _ = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        }
        for (addr, fd) in self.udp {
            tracing::info!(
                fd, %addr,
                "closing inherited UDP socket not claimed by any QUIC listener"
            );
            let _ = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        }
    }
}

/// Classify one fd: if it's a listening TCP/Unix socket, or a bound
/// UDP socket, insert it into the appropriate map.
///
/// Uses std's socket wrappers via ManuallyDrop so the fd is never closed
/// by the probe.  For stream sockets, SO_ACCEPTCONN filters out
/// connected/unbound sockets.  UDP has no listening state -- a bound
/// SOCK_DGRAM socket with an INET local address is what hypershunt needs to
/// adopt for QUIC, so it is detected via SO_TYPE instead.
fn classify_fd(
    fd: RawFd,
    tcp: &mut HashMap<SocketAddr, RawFd>,
    udp: &mut HashMap<SocketAddr, RawFd>,
    unix: &mut HashMap<PathBuf, RawFd>,
) {
    use nix::sys::socket::{
        SockType, getsockopt,
        sockopt::{AcceptConn, SockType as SockTypeOpt},
    };
    use std::mem::ManuallyDrop;
    use std::os::unix::io::{BorrowedFd, FromRawFd};

    // SAFETY: fd is open for the duration of this call.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };

    // Stream-listener path: SO_ACCEPTCONN tells us this is a listen(2)ed
    // socket.  Either TCP or Unix; probe both.
    if getsockopt(&borrowed, AcceptConn).unwrap_or(false) {
        // Probe as TCP (works for both IPv4 and IPv6).
        // ManuallyDrop ensures the fd is never closed by the probe.
        {
            let l = ManuallyDrop::new(unsafe {
                std::net::TcpListener::from_raw_fd(fd)
            });
            if let Ok(addr) = l.local_addr() {
                tcp.insert(addr, fd);
                return;
            }
        }

        // Probe as Unix domain socket.
        {
            let l = ManuallyDrop::new(unsafe {
                std::os::unix::net::UnixListener::from_raw_fd(fd)
            });
            if let Ok(addr) = l.local_addr()
                && let Some(path) = addr.as_pathname()
            {
                unix.insert(path.to_path_buf(), fd);
            }
        }
        return;
    }

    // Datagram path: SOCK_DGRAM with a bound local INET address means a
    // QUIC-eligible UDP socket (systemd ListenDatagram=, or one inherited
    // from a parent hypershunt across a seamless upgrade).
    if matches!(getsockopt(&borrowed, SockTypeOpt), Ok(SockType::Datagram)) {
        let s = ManuallyDrop::new(unsafe {
            std::net::UdpSocket::from_raw_fd(fd)
        });
        if let Ok(addr) = s.local_addr() {
            // Unbound UDP sockets report 0.0.0.0:0; skip them so we
            // don't collide with a genuine wildcard bind.
            if addr.port() != 0 {
                udp.insert(addr, fd);
            }
        }
    }
}

/// Enumerate all open file descriptors, excluding stdin/stdout/stderr.
fn open_fds() -> Vec<RawFd> {
    // On Linux, /proc/self/fd lists every open fd by name.
    #[cfg(target_os = "linux")]
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        return dir
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<RawFd>().ok())
            .filter(|&fd| fd > 2)
            .collect();
    }

    // Fallback for other Unix: probe fds 3..4096 via F_GETFD.
    use nix::fcntl::{FcntlArg, fcntl};
    use std::os::unix::io::BorrowedFd;
    (3_i32..4096)
        .filter(|&fd| {
            // SAFETY: checking if fd is valid; no ownership transfer.
            let b = unsafe { BorrowedFd::borrow_raw(fd) };
            fcntl(b, FcntlArg::F_GETFD).is_ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::io::{AsRawFd, IntoRawFd};

    /// A bound UDP socket is classified into the `udp` map keyed by its
    /// local address.  Mirrors the listening-TCP probe -- the QUIC
    /// listener relies on this to adopt systemd ListenDatagram= fds.
    #[test]
    fn classify_fd_detects_bound_udp() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let fd = sock.as_raw_fd();

        let mut tcp = HashMap::new();
        let mut udp = HashMap::new();
        let mut unix = HashMap::new();
        classify_fd(fd, &mut tcp, &mut udp, &mut unix);

        assert!(tcp.is_empty());
        assert!(unix.is_empty());
        assert_eq!(udp.get(&addr).copied(), Some(fd));
        // Keep `sock` alive so the fd stays valid for the assertion;
        // drop ends here.
        drop(sock);
    }

    /// A listening TCP socket still lands in the `tcp` map -- the UDP
    /// branch must not shadow the existing detection path.
    #[test]
    fn classify_fd_still_detects_tcp_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let fd = l.as_raw_fd();

        let mut tcp = HashMap::new();
        let mut udp = HashMap::new();
        let mut unix = HashMap::new();
        classify_fd(fd, &mut tcp, &mut udp, &mut unix);

        assert!(udp.is_empty());
        assert!(unix.is_empty());
        assert_eq!(tcp.get(&addr).copied(), Some(fd));
        drop(l);
    }

    /// take_udp removes the entry so the same fd cannot be claimed
    /// twice -- mirrors take_tcp's contract.
    #[test]
    fn take_udp_consumes_entry() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let fd = sock.into_raw_fd();

        let mut inh = InheritedSockets {
            tcp: HashMap::new(),
            udp: HashMap::from([(addr, fd)]),
            unix: HashMap::new(),
        };
        assert_eq!(inh.take_udp(addr), Some(fd));
        assert_eq!(inh.take_udp(addr), None);

        // Reclaim the fd so it gets closed at end of test.
        use std::os::unix::io::FromRawFd;
        unsafe { drop(std::net::UdpSocket::from_raw_fd(fd)) };
    }
}
