// h3get: a minimal HTTP/3 GET client used by hypershunt's shell-based
// integration tests.  Debian's `curl` package doesn't ship with
// HTTP/3 support, so we build our own using the same quinn + h3
// stack the server already pulls in.
//
// Usage:
//   h3get [--skip-verify] [--max-time SECS] [-H "Header: value"]... URL
//
// Output:
//   stdout:  response body
//   stderr:  "HTTP/3 <status>\n<header>: <value>\n..."
//   exit code:
//     0  success (any 2xx/3xx)
//     1  transport / handshake error
//     2  timed out
//     3  upstream returned a 4xx or 5xx
//     4  argument error
//
// Designed to mimic `curl -sS -o - -D >&2 --http3-only` so the
// existing shell assertion helpers can wrap it the same way.

use bytes::Buf;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match Opts::parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("h3get: {e}");
            return std::process::ExitCode::from(4);
        }
    };

    match run(opts).await {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e) => {
            eprintln!("h3get: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

struct Opts {
    url: hyper::Uri,
    skip_verify: bool,
    max_time: Duration,
    headers: Vec<(String, String)>,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut url: Option<hyper::Uri> = None;
        let mut skip_verify = false;
        let mut max_time = Duration::from_secs(10);
        let mut headers = Vec::new();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--skip-verify" | "-k" => skip_verify = true,
                "--max-time" => {
                    i += 1;
                    let s = args
                        .get(i)
                        .ok_or("--max-time requires a value")?;
                    let secs: u64 = s
                        .parse()
                        .map_err(|_| format!("bad --max-time: {s}"))?;
                    max_time = Duration::from_secs(secs);
                }
                "-H" | "--header" => {
                    i += 1;
                    let s = args
                        .get(i)
                        .ok_or("-H requires a value")?;
                    let (name, value) = s
                        .split_once(':')
                        .ok_or_else(|| {
                            format!("bad header (need 'Name: value'): {s}")
                        })?;
                    headers.push((
                        name.trim().to_string(),
                        value.trim().to_string(),
                    ));
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown flag: {other}"));
                }
                _ => {
                    url = Some(args[i].parse().map_err(|e| {
                        format!("bad URL '{}': {e}", args[i])
                    })?);
                }
            }
            i += 1;
        }
        let url = url.ok_or("missing URL")?;
        if url.scheme_str() != Some("https") {
            return Err("URL must be https://".into());
        }
        Ok(Self { url, skip_verify, max_time, headers })
    }
}

async fn run(opts: Opts) -> Result<u8, String> {
    let fut = do_request(&opts);
    match tokio::time::timeout(opts.max_time, fut).await {
        Err(_) => Ok(2), // timed out
        Ok(Err(e)) => Err(e),
        Ok(Ok(code)) => Ok(code),
    }
}

async fn do_request(opts: &Opts) -> Result<u8, String> {
    // Build a rustls ClientConfig with `h3` ALPN.  Either webpki
    // roots (default) or the permissive skip-verify path for tests
    // against self-signed listeners.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let mut crypto = if opts.skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_cfg =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| format!("rustls/quic: {e}"))?;
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));

    // Resolve the URL's authority to a SocketAddr.  Hostnames are
    // looked up via tokio's default resolver; literal IPs short-
    // circuit DNS.  Take the first result.
    let host = opts
        .url
        .host()
        .ok_or_else(|| "URL has no host".to_string())?;
    let port = opts.url.port_u16().unwrap_or(443);
    let addr: std::net::SocketAddr =
        tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("resolve {host}:{port}: {e}"))?
            .next()
            .ok_or_else(|| {
                format!("no addresses for {host}:{port}")
            })?;

    // Bind the client UDP socket in the same family as the peer.
    // A v6 dual-stack socket can in principle reach v4 addresses,
    // but some platforms (and some kernel configs) drop those
    // packets silently.  Matching families avoids the surprise.
    let bind_addr: std::net::SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|e| format!("quinn client endpoint: {e}"))?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(addr, host)
        .map_err(|e| format!("connect setup: {e}"))?
        .await
        .map_err(|e| format!("quinn handshake: {e}"))?;

    let h3q = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3q)
        .await
        .map_err(|e| format!("h3 client: {e}"))?;
    let _drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Build the request.  HTTP/3 carries the target host in the
    // :authority pseudo-header, which hyper::Request::builder()
    // derives from the URI for us.
    let mut req_builder = hyper::Request::builder()
        .method("GET")
        .uri(opts.url.clone());
    for (name, value) in &opts.headers {
        req_builder = req_builder.header(name, value);
    }
    let req = req_builder
        .body(())
        .map_err(|e| format!("build request: {e}"))?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| format!("send_request: {e}"))?;
    stream
        .finish()
        .await
        .map_err(|e| format!("finish: {e}"))?;

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| format!("recv_response: {e}"))?;

    let status = resp.status();
    eprintln!("HTTP/3 {} {}", status.as_u16(), status.canonical_reason().unwrap_or(""));
    for (k, v) in resp.headers() {
        if let Ok(vs) = v.to_str() {
            eprintln!("{}: {}", k.as_str(), vs);
        }
    }

    // Stream the body to stdout.
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    while let Some(mut chunk) =
        stream.recv_data().await.map_err(|e| format!("recv_data: {e}"))?
    {
        let n = chunk.remaining();
        let bytes = chunk.copy_to_bytes(n);
        out.write_all(&bytes).map_err(|e| format!("stdout: {e}"))?;
    }
    out.flush().ok();

    let code = if status.is_success() || status.is_redirection() {
        0
    } else {
        3
    };
    Ok(code)
}

/// rustls verifier that accepts any cert.  Behind `--skip-verify`
/// so the integration suite can talk to self-signed test listeners.
#[derive(Debug)]
struct SkipVerify;

mod skip_verify_impl {
    use super::SkipVerify;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    impl ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }
}
