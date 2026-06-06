// HAProxy PROXY protocol header builder (v1 text and v2 binary) and
// inbound header parser.  The builder is used by the TCP/HTTP proxy
// handlers to forward the real client address to backends.  The parser
// is used by listeners with `accept-proxy-protocol` configured to
// recover the real client address from a load balancer upstream.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::config::ProxyProtocolVersion;

/// Build a PROXY protocol header to prepend to the backend connection.
///
/// `src` is the original client address; `dst` is hypershunt's local address
/// (what the client was connecting to).
pub fn build_header(
    version: ProxyProtocolVersion,
    src: SocketAddr,
    dst: SocketAddr,
) -> Vec<u8> {
    match version {
        ProxyProtocolVersion::V1 => build_v1(src, dst),
        ProxyProtocolVersion::V2 => build_v2(src, dst),
    }
}

// -- PROXY protocol v1 (text) --------------------------------------

// Format: "PROXY {TCP4|TCP6} {src_ip} {dst_ip} {src_port} {dst_port}\r\n"
fn build_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let proto = match src.ip() {
        IpAddr::V4(_) => "TCP4",
        IpAddr::V6(_) => "TCP6",
    };
    format!(
        "PROXY {proto} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port(),
    )
    .into_bytes()
}

// -- PROXY protocol v2 (binary) -----------------------------------

// Fixed 12-byte signature that marks a v2 PROXY header.
const V2_SIGNATURE: &[u8; 12] =
    b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

fn build_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 36); // max size (IPv6)
    buf.extend_from_slice(V2_SIGNATURE);

    // Version (high nibble = 2) + command (low nibble = 1 = PROXY).
    buf.push(0x21);

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            buf.push(0x11); // AF_INET + STREAM
            buf.extend_from_slice(&12u16.to_be_bytes()); // addr block length
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            buf.push(0x21); // AF_INET6 + STREAM
            buf.extend_from_slice(&36u16.to_be_bytes()); // addr block length
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
        _ => {
            // Mixed address families -- emit UNSPEC/UNSPEC with no addresses.
            buf.push(0x00);
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    buf
}

// -- Builders for non-TCP connections ------------------------------

/// v1 header for connections where the original addresses are unknown
/// (e.g. the client connected over a Unix domain socket).
pub fn build_v1_unknown() -> Vec<u8> {
    b"PROXY UNKNOWN\r\n".to_vec()
}

/// v2 UNSPEC header: PROXY command with no address block.
/// Emitted when the peer is a Unix socket and no paths are available.
pub fn build_v2_unspec() -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(V2_SIGNATURE);
    buf.push(0x21); // version=2, command=PROXY
    buf.push(0x00); // AF_UNSPEC — no address family
    buf.extend_from_slice(&0u16.to_be_bytes()); // zero-length address block
    buf
}

/// v2 AF_UNIX header: PROXY command with a 216-byte address block
/// containing null-padded 108-byte source and destination socket paths.
/// Pass `None` for an unknown or anonymous path (block bytes stay zero).
pub fn build_v2_unix(src: Option<&Path>, dst: Option<&Path>) -> Vec<u8> {
    const BLOCK: usize = 216; // 108 + 108
    let mut buf = Vec::with_capacity(16 + BLOCK);
    buf.extend_from_slice(V2_SIGNATURE);
    buf.push(0x21); // version=2, command=PROXY
    buf.push(0x31); // AF_UNIX + STREAM
    buf.extend_from_slice(&(BLOCK as u16).to_be_bytes());
    for opt in [src, dst] {
        let mut slot = [0u8; 108];
        if let Some(p) = opt {
            // Truncate at 107 to ensure the path is null-terminated.
            let raw = p.as_os_str().as_encoded_bytes();
            let n = raw.len().min(107);
            slot[..n].copy_from_slice(&raw[..n]);
        }
        buf.extend_from_slice(&slot);
    }
    buf
}

// -- Inbound parser ------------------------------------------------

/// Parse a PROXY protocol header from the beginning of a freshly
/// accepted stream.
///
/// Returns `Ok(Some((src, dst)))` with the real client and server
/// addresses on success.  Returns `Ok(None)` when the header carries
/// an UNKNOWN (v1) or LOCAL (v2) address — the caller should keep the
/// original TCP peer address.  Returns `Err` for a malformed header;
/// the caller should close the connection without sending a response.
///
/// The stream is positioned immediately after the header on return, so
/// TLS or HTTP layers can read from it without any further adjustment.
pub async fn parse_incoming<R>(
    reader: &mut R,
    version: ProxyProtocolVersion,
) -> io::Result<Option<(SocketAddr, SocketAddr)>>
where
    R: AsyncRead + Unpin,
{
    match version {
        ProxyProtocolVersion::V1 => parse_v1(reader).await,
        ProxyProtocolVersion::V2 => parse_v2(reader).await,
    }
}

// Parse a v1 text header: "PROXY {TCP4|TCP6|UNKNOWN} src dst sport dport\r\n"
// Max length per spec is 108 bytes.
async fn parse_v1<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
    let mut buf = [0u8; 108];
    let mut pos = 0;
    // Read byte-by-byte until \r\n so we consume exactly the header.
    loop {
        if pos >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PROXY v1 header exceeds 108 bytes",
            ));
        }
        reader.read_exact(&mut buf[pos..pos + 1]).await?;
        pos += 1;
        if pos >= 2 && buf[pos - 2] == b'\r' && buf[pos - 1] == b'\n' {
            break;
        }
    }
    // Trim the trailing \r\n.
    let line = std::str::from_utf8(&buf[..pos - 2]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v1 header is not valid UTF-8",
        )
    })?;
    let mut parts = line.splitn(6, ' ');
    if parts.next() != Some("PROXY") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v1 header missing 'PROXY' prefix",
        ));
    }
    let proto = parts.next().unwrap_or("");
    if proto == "UNKNOWN" {
        return Ok(None);
    }
    let src_ip_s = parts.next().ok_or_else(bad_v1)?;
    let dst_ip_s = parts.next().ok_or_else(bad_v1)?;
    let src_port: u16 = parts
        .next()
        .ok_or_else(bad_v1)?
        .parse()
        .map_err(|_| bad_v1())?;
    let dst_port: u16 = parts
        .next()
        .ok_or_else(bad_v1)?
        .parse()
        .map_err(|_| bad_v1())?;
    let (src, dst) = match proto {
        "TCP4" => {
            let s: Ipv4Addr = src_ip_s.parse().map_err(|_| bad_v1())?;
            let d: Ipv4Addr = dst_ip_s.parse().map_err(|_| bad_v1())?;
            (
                SocketAddr::new(IpAddr::V4(s), src_port),
                SocketAddr::new(IpAddr::V4(d), dst_port),
            )
        }
        "TCP6" => {
            let s: Ipv6Addr = src_ip_s.parse().map_err(|_| bad_v1())?;
            let d: Ipv6Addr = dst_ip_s.parse().map_err(|_| bad_v1())?;
            (
                SocketAddr::new(IpAddr::V6(s), src_port),
                SocketAddr::new(IpAddr::V6(d), dst_port),
            )
        }
        _ => return Err(bad_v1()),
    };
    Ok(Some((src, dst)))
}

fn bad_v1() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed PROXY v1 header")
}

// Parse a v2 binary header.  Fixed 16-byte prefix followed by a
// variable-length address block whose length is in bytes 14-15.
async fn parse_v2<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
    let mut fixed = [0u8; 16];
    reader.read_exact(&mut fixed).await?;

    if &fixed[..12] != V2_SIGNATURE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v2 signature mismatch",
        ));
    }
    let ver = fixed[12] >> 4;
    let cmd = fixed[12] & 0x0F;
    if ver != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v2 version field must be 2",
        ));
    }
    let family = fixed[13] >> 4;
    let addr_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;

    let mut block = vec![0u8; addr_len];
    reader.read_exact(&mut block).await?;

    // LOCAL (0): discard addresses; caller keeps the TCP peer address.
    if cmd == 0 {
        return Ok(None);
    }
    if cmd != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v2 unknown command byte",
        ));
    }
    match family {
        0 => Ok(None), // UNSPEC
        1 => {
            // AF_INET: src_ip(4) dst_ip(4) src_port(2) dst_port(2)
            if block.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY v2 AF_INET address block too short",
                ));
            }
            let src = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    block[0], block[1], block[2], block[3],
                )),
                u16::from_be_bytes([block[8], block[9]]),
            );
            let dst = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    block[4], block[5], block[6], block[7],
                )),
                u16::from_be_bytes([block[10], block[11]]),
            );
            Ok(Some((src, dst)))
        }
        2 => {
            // AF_INET6: src_ip(16) dst_ip(16) src_port(2) dst_port(2)
            if block.len() < 36 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY v2 AF_INET6 address block too short",
                ));
            }
            // The length check above guarantees both slices are
            // exactly 16 bytes; `expect()` documents the invariant
            // so a future caller can't introduce a regression.
            let src = SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&block[0..16])
                        .expect("16-byte src after length check"),
                )),
                u16::from_be_bytes([block[32], block[33]]),
            );
            let dst = SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&block[16..32])
                        .expect("16-byte dst after length check"),
                )),
                u16::from_be_bytes([block[34], block[35]]),
            );
            Ok(Some((src, dst)))
        }
        // AF_UNIX (3): no IP addresses to extract.
        _ => Ok(None),
    }
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    fn v6(ip: [u8; 16], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
    }

    // -- v1 --------------------------------------------------------

    #[test]
    fn v1_ipv4_format() {
        let header =
            build_v1(v4([192, 168, 1, 100], 54321), v4([10, 0, 0, 1], 3306));
        let s = std::str::from_utf8(&header).unwrap();
        assert_eq!(s, "PROXY TCP4 192.168.1.100 10.0.0.1 54321 3306\r\n");
    }

    #[test]
    fn v1_ipv6_format() {
        let src = "::1".parse::<IpAddr>().unwrap();
        let dst = "::2".parse::<IpAddr>().unwrap();
        let header =
            build_v1(SocketAddr::new(src, 1234), SocketAddr::new(dst, 5432));
        let s = std::str::from_utf8(&header).unwrap();
        assert_eq!(s, "PROXY TCP6 ::1 ::2 1234 5432\r\n");
    }

    #[test]
    fn v1_ends_with_crlf() {
        let h = build_v1(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert!(h.ends_with(b"\r\n"));
    }

    // -- v2 --------------------------------------------------------

    #[test]
    fn v2_starts_with_signature() {
        let h = build_v2(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert_eq!(&h[..12], V2_SIGNATURE);
    }

    #[test]
    fn v2_version_and_command() {
        let h = build_v2(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert_eq!(h[12], 0x21, "version=2, command=PROXY");
    }

    #[test]
    fn v2_ipv4_family_and_length() {
        let h = build_v2(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert_eq!(h[13], 0x11, "AF_INET + STREAM");
        let len = u16::from_be_bytes([h[14], h[15]]);
        assert_eq!(len, 12, "4+4+2+2 bytes for IPv4 address block");
        assert_eq!(h.len(), 28, "16 fixed + 12 address bytes");
    }

    #[test]
    fn v2_ipv4_addresses_and_ports() {
        let h =
            build_v2(v4([192, 168, 1, 100], 54321), v4([10, 0, 0, 1], 3306));
        assert_eq!(&h[16..20], &[192, 168, 1, 100]); // src IP
        assert_eq!(&h[20..24], &[10, 0, 0, 1]); // dst IP
        let src_port = u16::from_be_bytes([h[24], h[25]]);
        let dst_port = u16::from_be_bytes([h[26], h[27]]);
        assert_eq!(src_port, 54321);
        assert_eq!(dst_port, 3306);
    }

    #[test]
    fn v2_ipv6_family_and_length() {
        let h = build_v2(
            v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 1234),
            v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 5432),
        );
        assert_eq!(h[13], 0x21, "AF_INET6 + STREAM");
        let len = u16::from_be_bytes([h[14], h[15]]);
        assert_eq!(len, 36, "16+16+2+2 bytes for IPv6 address block");
        assert_eq!(h.len(), 52, "16 fixed + 36 address bytes");
    }

    #[test]
    fn build_header_dispatches_to_correct_version() {
        let src = v4([1, 2, 3, 4], 1000);
        let dst = v4([5, 6, 7, 8], 2000);
        let v1 = build_header(ProxyProtocolVersion::V1, src, dst);
        let v2 = build_header(ProxyProtocolVersion::V2, src, dst);
        // v1 is text; v2 starts with the binary signature
        assert!(v1.starts_with(b"PROXY "));
        assert!(v2.starts_with(V2_SIGNATURE));
    }

    // -- parse_incoming v1 -----------------------------------------

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    fn parse_v1_bytes(
        bytes: &[u8],
    ) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        rt().block_on(parse_v1(&mut cursor))
    }

    #[test]
    fn parse_v1_tcp4() {
        let (src, dst) =
            parse_v1_bytes(b"PROXY TCP4 192.168.1.100 10.0.0.1 54321 3306\r\n")
                .unwrap()
                .unwrap();
        assert_eq!(src, "192.168.1.100:54321".parse::<SocketAddr>().unwrap());
        assert_eq!(dst, "10.0.0.1:3306".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_v1_tcp6() {
        let (src, dst) = parse_v1_bytes(b"PROXY TCP6 ::1 ::2 1234 5432\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(src, "[::1]:1234".parse::<SocketAddr>().unwrap());
        assert_eq!(dst, "[::2]:5432".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_v1_unknown_returns_none() {
        let result = parse_v1_bytes(b"PROXY UNKNOWN\r\n").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_v1_roundtrip() {
        // Build a v1 header with the builder, then parse it back.
        let src = v4([192, 168, 1, 100], 54321);
        let dst = v4([10, 0, 0, 1], 3306);
        let header = build_v1(src, dst);
        let (parsed_src, parsed_dst) =
            parse_v1_bytes(&header).unwrap().unwrap();
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn parse_v1_bad_prefix_errors() {
        let result = parse_v1_bytes(b"GARBAGE TCP4 1.2.3.4 5.6.7.8 1 2\r\n");
        assert!(result.is_err());
    }

    // -- parse_incoming v2 -----------------------------------------

    fn parse_v2_bytes(
        bytes: &[u8],
    ) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        rt().block_on(parse_v2(&mut cursor))
    }

    #[test]
    fn parse_v2_ipv4_roundtrip() {
        let src = v4([192, 168, 1, 100], 54321);
        let dst = v4([10, 0, 0, 1], 3306);
        let header = build_v2(src, dst);
        let (parsed_src, parsed_dst) =
            parse_v2_bytes(&header).unwrap().unwrap();
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn parse_v2_ipv6_roundtrip() {
        let src = v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 1234);
        let dst = v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 5432);
        let header = build_v2(src, dst);
        let (parsed_src, parsed_dst) =
            parse_v2_bytes(&header).unwrap().unwrap();
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn parse_v2_local_command_returns_none() {
        // Build a LOCAL header manually (command=0x20, family=0x00, len=0).
        let mut header = Vec::new();
        header.extend_from_slice(V2_SIGNATURE);
        header.push(0x20); // version=2, command=LOCAL
        header.push(0x00); // UNSPEC
        header.extend_from_slice(&0u16.to_be_bytes());
        let result = parse_v2_bytes(&header).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_v2_bad_signature_errors() {
        let mut header = vec![0u8; 16];
        header[0] = 0xFF; // corrupt the signature
        let result = parse_v2_bytes(&header);
        assert!(result.is_err());
    }

    // -- build_v1_unknown / build_v2_unspec / build_v2_unix ----------

    #[test]
    fn v1_unknown_is_exact_bytes() {
        assert_eq!(build_v1_unknown(), b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn v2_unspec_structure() {
        let h = build_v2_unspec();
        assert_eq!(h.len(), 16);
        assert_eq!(&h[..12], V2_SIGNATURE);
        assert_eq!(h[12], 0x21, "PROXY command");
        assert_eq!(h[13], 0x00, "AF_UNSPEC");
        let len = u16::from_be_bytes([h[14], h[15]]);
        assert_eq!(len, 0, "no address block");
    }

    #[test]
    fn v2_unspec_parses_as_none() {
        let h = build_v2_unspec();
        let result = parse_v2_bytes(&h).unwrap();
        assert!(result.is_none(), "UNSPEC should return None");
    }

    #[test]
    fn v2_unix_structure() {
        let src_p = std::path::Path::new("/run/client.sock");
        let dst_p = std::path::Path::new("/run/hypershunt.sock");
        let h = build_v2_unix(Some(src_p), Some(dst_p));
        assert_eq!(h.len(), 232, "16 fixed + 216 address bytes");
        assert_eq!(&h[..12], V2_SIGNATURE);
        assert_eq!(h[12], 0x21, "PROXY command");
        assert_eq!(h[13], 0x31, "AF_UNIX + STREAM");
        let addr_len = u16::from_be_bytes([h[14], h[15]]);
        assert_eq!(addr_len, 216);
    }

    #[test]
    fn v2_unix_encodes_paths() {
        let dst_p = std::path::Path::new("/run/hypershunt.sock");
        let h = build_v2_unix(None, Some(dst_p));
        // src slot (bytes 16–123) should be all zeros for None
        assert!(h[16..124].iter().all(|&b| b == 0), "src slot zero");
        // dst slot (bytes 124–231) should start with the path
        let path_bytes = b"/run/hypershunt.sock";
        assert_eq!(&h[124..124 + path_bytes.len()], path_bytes);
        // remainder of dst slot should be zero-padded
        let after = 124 + path_bytes.len();
        assert!(h[after..232].iter().all(|&b| b == 0));
    }

    #[test]
    fn v2_unix_parses_as_none() {
        // AF_UNIX carries paths, not IP addresses; parser should return None.
        let h = build_v2_unix(
            Some(std::path::Path::new("/src.sock")),
            Some(std::path::Path::new("/dst.sock")),
        );
        let result = parse_v2_bytes(&h).unwrap();
        assert!(result.is_none(), "AF_UNIX should return None from parser");
    }

    #[test]
    fn v2_unix_truncates_overlong_path() {
        // Path longer than 107 bytes must be silently truncated.
        let long = "a".repeat(200);
        let p = std::path::Path::new(&long);
        let h = build_v2_unix(Some(p), None);
        assert_eq!(h.len(), 232);
        // Byte 107 of the src slot (offset 16+107 = 123) must be 0
        // (null terminator, not part of the truncated path).
        assert_eq!(h[16 + 107], 0);
    }
}
