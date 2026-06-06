// Explicit socket-kind model for listener binds and proxy upstreams.
//
// Every listener and every proxy upstream is described by a URL with a
// required scheme:
//
//   tcp://host:port            TCP, connection-oriented
//   udp://host:port            UDP, datagram
//   unix-stream:/path          AF_UNIX SOCK_STREAM
//   unix-dgram:/path           AF_UNIX SOCK_DGRAM
//   unix-seqpacket:/path       AF_UNIX SOCK_SEQPACKET
//
// There is no legacy form: bare `host:port`, `udp:host:port`, and
// `unix:/path` are all rejected at parse time.  Hypershunt is at 1.0-rc and
// the breakage window is open; the strict grammar removes the implicit
// rules the old `Transport { Tcp, Udp }` enum encoded and makes
// stream/message symmetry explicit.

use anyhow::{Result, anyhow, bail};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Concrete kind of socket hypershunt will bind to (for a listener) or
/// connect to (for an upstream).  The "stream" vs "message" split is
/// the key invariant downstream code keys off: stream listeners must
/// proxy by connection to stream upstreams, and message listeners
/// must proxy by datagram to message upstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketKind {
    TcpStream,
    UdpDgram,
    UnixStream,
    UnixDgram,
    UnixSeqpacket,
}

impl SocketKind {
    /// True for byte-stream sockets: TCP and unix-stream.  These
    /// listeners run an accept loop and pair each accepted
    /// connection with one upstream connection; TLS terminates
    /// here.  The "byte" in the name distinguishes the shape from
    /// the kernel's SOCK_STREAM family -- SOCK_SEQPACKET is also a
    /// "stream" in the kernel sense but preserves message
    /// boundaries, so it is a datagram stream in our model.
    pub fn is_byte_stream(self) -> bool {
        matches!(self, SocketKind::TcpStream | SocketKind::UnixStream)
    }

    /// True for datagram-stream sockets: UDP, unix-dgram, and
    /// unix-seqpacket.  Message boundaries are preserved on read;
    /// QUIC and (future) DTLS terminate here on the UDP arm.
    pub fn is_datagram_stream(self) -> bool {
        !self.is_byte_stream()
    }

    /// The address family the kind lives in.  Used by the binder to
    /// decide whether to parse the location as `host:port` or a path.
    #[allow(dead_code)] // surfaced via `AddrLocation` discrimination today
    pub fn family(self) -> AddrFamily {
        match self {
            SocketKind::TcpStream | SocketKind::UdpDgram => AddrFamily::Inet,
            SocketKind::UnixStream
            | SocketKind::UnixDgram
            | SocketKind::UnixSeqpacket => AddrFamily::Unix,
        }
    }

    /// Scheme string used in config syntax.  Round-trips through
    /// `BoundAddr::parse`.
    pub fn scheme(self) -> &'static str {
        match self {
            SocketKind::TcpStream => "tcp",
            SocketKind::UdpDgram => "udp",
            SocketKind::UnixStream => "unix-stream",
            SocketKind::UnixDgram => "unix-dgram",
            SocketKind::UnixSeqpacket => "unix-seqpacket",
        }
    }
}

/// Address family — Inet sockets carry a `host:port`, Unix sockets
/// carry a filesystem path.  Kept as a separate enum so the parser
/// can decide *how* to parse the location once the scheme settles
/// the kind.  External call sites discriminate via `AddrLocation`
/// directly today; the enum is exported for future extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AddrFamily {
    Inet,
    Unix,
}

/// Parsed bind/upstream location.  `Inet` carries a resolved
/// `SocketAddr` so unresolvable host:port pairs fail at config parse
/// time, not at bind time; `Unix` keeps the raw `PathBuf` because
/// path validation belongs to the binder (it has to know whether the
/// path will be created or adopted from systemd).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AddrLocation {
    Inet(SocketAddr),
    Unix(PathBuf),
}

/// Fully parsed bind or upstream address: kind + location.  Listener
/// and proxy config both store one of these instead of a raw string.
///
/// `PartialEq` / `Eq` / `Hash` are derived so `BoundAddr` can be used
/// as a hash-map key (reload diff, inherited-socket lookup).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundAddr {
    pub kind: SocketKind,
    pub location: AddrLocation,
}

impl std::fmt::Display for BoundAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_url())
    }
}

impl BoundAddr {
    /// Render back as the canonical URL form.  Used for log lines and
    /// the `bind` field returned by the status page.
    pub fn to_url(&self) -> String {
        match (&self.kind, &self.location) {
            (k, AddrLocation::Inet(sa)) => {
                // tcp://host:port style — bracketed v6 already in sa display.
                format!("{}://{}", k.scheme(), sa)
            }
            (k, AddrLocation::Unix(path)) => {
                // unix-stream:/path style — single colon, no //.
                format!("{}:{}", k.scheme(), path.display())
            }
        }
    }

    /// Return the inet `SocketAddr` if this is an inet kind, else None.
    /// Convenience for places that previously did
    /// `bind.parse::<SocketAddr>()`.
    pub fn as_inet(&self) -> Option<SocketAddr> {
        match &self.location {
            AddrLocation::Inet(sa) => Some(*sa),
            _ => None,
        }
    }

    /// Return the unix path if this is a unix kind, else None.
    pub fn as_unix_path(&self) -> Option<&std::path::Path> {
        match &self.location {
            AddrLocation::Unix(p) => Some(p),
            _ => None,
        }
    }

    /// Parse one of the strict URL forms.  See module docs for the
    /// full grammar.  All other inputs return an error naming the
    /// expected schemes.
    pub fn parse(s: &str) -> Result<Self> {
        // Inet schemes use `://` because authority semantics apply
        // (the location is a network host).  Unix schemes use `:`
        // because the location is just a filesystem path, no
        // authority component.
        if let Some(rest) = s.strip_prefix("tcp://") {
            let sa = parse_inet(rest)?;
            return Ok(BoundAddr {
                kind: SocketKind::TcpStream,
                location: AddrLocation::Inet(sa),
            });
        }
        if let Some(rest) = s.strip_prefix("udp://") {
            let sa = parse_inet(rest)?;
            return Ok(BoundAddr {
                kind: SocketKind::UdpDgram,
                location: AddrLocation::Inet(sa),
            });
        }
        if let Some(rest) = s.strip_prefix("unix-stream:") {
            return Ok(BoundAddr {
                kind: SocketKind::UnixStream,
                location: AddrLocation::Unix(parse_unix_path(rest)?),
            });
        }
        if let Some(rest) = s.strip_prefix("unix-dgram:") {
            return Ok(BoundAddr {
                kind: SocketKind::UnixDgram,
                location: AddrLocation::Unix(parse_unix_path(rest)?),
            });
        }
        if let Some(rest) = s.strip_prefix("unix-seqpacket:") {
            return Ok(BoundAddr {
                kind: SocketKind::UnixSeqpacket,
                location: AddrLocation::Unix(parse_unix_path(rest)?),
            });
        }
        bail!(
            "address `{s}` is missing a scheme; expected one of \
             tcp://host:port, udp://host:port, unix-stream:/path, \
             unix-dgram:/path, unix-seqpacket:/path"
        )
    }
}

impl FromStr for BoundAddr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        BoundAddr::parse(s)
    }
}

fn parse_inet(rest: &str) -> Result<SocketAddr> {
    // `host:port` -- bracketed IPv6 (`[::1]:80`) parses directly via
    // SocketAddr's FromStr.  Hostnames are NOT accepted because hypershunt
    // binds the address, not resolves it; if a caller wants DNS they
    // should resolve before configuring (matches the old behaviour
    // for tcp binds).
    rest.parse::<SocketAddr>().map_err(|e| {
        anyhow!(
            "invalid host:port `{rest}` ({e}); use a literal IP \
             address with a numeric port"
        )
    })
}

fn parse_unix_path(rest: &str) -> Result<PathBuf> {
    if rest.is_empty() {
        bail!("unix socket path must not be empty");
    }
    Ok(PathBuf::from(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_v4() {
        let a = BoundAddr::parse("tcp://127.0.0.1:8080").unwrap();
        assert_eq!(a.kind, SocketKind::TcpStream);
        assert!(a.kind.is_byte_stream());
        assert_eq!(
            a.as_inet().unwrap().to_string(),
            "127.0.0.1:8080"
        );
    }

    #[test]
    fn parses_tcp_v6() {
        let a = BoundAddr::parse("tcp://[::1]:443").unwrap();
        assert!(matches!(a.kind, SocketKind::TcpStream));
        assert_eq!(a.as_inet().unwrap().port(), 443);
    }

    #[test]
    fn parses_udp() {
        let a = BoundAddr::parse("udp://0.0.0.0:53").unwrap();
        assert_eq!(a.kind, SocketKind::UdpDgram);
        assert!(a.kind.is_datagram_stream());
    }

    #[test]
    fn parses_unix_variants() {
        for (s, want) in [
            ("unix-stream:/run/a.sock", SocketKind::UnixStream),
            ("unix-dgram:/run/b.sock", SocketKind::UnixDgram),
            ("unix-seqpacket:/run/c.sock", SocketKind::UnixSeqpacket),
        ] {
            let a = BoundAddr::parse(s).unwrap();
            assert_eq!(a.kind, want);
            assert_eq!(a.kind.family(), AddrFamily::Unix);
        }
    }

    #[test]
    fn rejects_bare_host_port() {
        let err = BoundAddr::parse("127.0.0.1:8080").unwrap_err();
        assert!(err.to_string().contains("missing a scheme"));
    }

    #[test]
    fn rejects_legacy_udp_prefix() {
        // The old syntax was `udp:host:port` (single colon, no //).
        // Must be rejected so users get a clear error.
        let err = BoundAddr::parse("udp:127.0.0.1:53").unwrap_err();
        assert!(err.to_string().contains("missing a scheme"));
    }

    #[test]
    fn rejects_legacy_unix_prefix() {
        let err = BoundAddr::parse("unix:/run/a.sock").unwrap_err();
        assert!(err.to_string().contains("missing a scheme"));
    }

    #[test]
    fn rejects_empty_unix_path() {
        let err = BoundAddr::parse("unix-stream:").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_hostname() {
        let err = BoundAddr::parse("tcp://example.com:80").unwrap_err();
        assert!(err.to_string().contains("invalid host:port"));
    }

    #[test]
    fn to_url_round_trips() {
        for s in [
            "tcp://127.0.0.1:8080",
            "udp://0.0.0.0:53",
            "unix-stream:/run/a.sock",
            "unix-dgram:/run/b.sock",
            "unix-seqpacket:/run/c.sock",
        ] {
            assert_eq!(BoundAddr::parse(s).unwrap().to_url(), s);
        }
    }

    #[test]
    fn round_trips_v6_in_url() {
        let a = BoundAddr::parse("tcp://[::1]:443").unwrap();
        assert_eq!(a.to_url(), "tcp://[::1]:443");
    }
}
