// Transparent upgrade / tunnel proxying across h1, h2 (RFC 8441
// extended CONNECT) and h3 (RFC 9220 extended CONNECT).
//
// All five "upgraded byte stream" sources surface through one
// `UpgradedStream` trait so the bidi pump (`copy_bidirectional`)
// doesn't care whether bytes are flowing over an h1-101-switched
// TCP socket, an h2 multiplexed CONNECT stream, or an h3 bidi QUIC
// stream.  Per-protocol adapters in this module turn each into the
// `AsyncRead + AsyncWrite` shape the pump consumes.

use hyper::header::{CONNECTION, HeaderValue, UPGRADE};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod ws;
pub use ws::MaskMode;

/// Anything we can pump bidirectional bytes over.  The trait is a
/// thin marker so we can name `Box<dyn UpgradedStream>` cleanly --
/// `dyn AsyncRead + AsyncWrite + Send + Unpin` is not legal Rust
/// (only one non-auto trait per `dyn`).
pub trait UpgradedStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> UpgradedStream for T where
    T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized
{
}

/// Boxed upgraded stream.  Owns its underlying IO -- when the box
/// is dropped, the socket / stream / QUIC bidi closes.
pub type BoxedUpgradedStream = Box<dyn UpgradedStream>;

/// Run the bidirectional copy between two upgraded streams until
/// either side closes (or errors).  Returns `(bytes_a_to_b,
/// bytes_b_to_a)` on a clean close, `Err` on transport failure
/// (which we log + drop -- there is no recovery).
pub async fn pump(
    mut a: BoxedUpgradedStream,
    mut b: BoxedUpgradedStream,
) -> std::io::Result<(u64, u64)> {
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// Bidirectional pump for a WebSocket tunnel that crosses the
/// h1<->h2/h3 masking boundary (issue #35).
///
/// Only the *client-to-server* direction (`inbound` -> `upstream`)
/// crosses the boundary, so it runs through the frame-mask
/// `translate_masking` codec; `mode` selects unmask (h1 client ->
/// h2/h3 backend) or mask (h2/h3 client -> h1 backend).  Server-to-
/// client frames are unmasked in every protocol, so that half is a
/// verbatim byte copy.
///
/// Each half shuts down the peer's write side when it finishes so a
/// WebSocket Close in one direction propagates EOF to the other,
/// mirroring `copy_bidirectional`'s half-close handling.
pub async fn pump_websocket(
    inbound: BoxedUpgradedStream,
    upstream: BoxedUpgradedStream,
    mode: MaskMode,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let (mut in_r, mut in_w) = tokio::io::split(inbound);
    let (mut up_r, mut up_w) = tokio::io::split(upstream);

    let client_to_server = async {
        let res =
            ws::translate_masking(&mut in_r, &mut up_w, mode).await;
        let _ = up_w.shutdown().await;
        res
    };
    let server_to_client = async {
        let res =
            tokio::io::copy(&mut up_r, &mut in_w).await.map(|_| ());
        let _ = in_w.shutdown().await;
        res
    };

    let (c2s, s2c) = tokio::join!(client_to_server, server_to_client);
    c2s.and(s2c)
}

// -- Inbound detection + extension marker --------------------------

/// Marker stashed on `Request::extensions` when an inbound request
/// is an HTTP upgrade -- h1 `Upgrade:`, h2 RFC 8441 extended
/// CONNECT, or h3 RFC 9220 extended CONNECT.  The proxy handler
/// pulls this out before normal dispatch and switches to the
/// tunnel path.
///
/// Fields:
/// - `protocol` -- the upgraded protocol name (e.g. "websocket",
///   "h2c").  Always ASCII, lowercased for h1 `Upgrade:` parsing
///   convenience; for h2/h3 extended CONNECT it's the `:protocol`
///   pseudo-header value verbatim.
/// - `inbound` -- the source-protocol enum so the dispatcher can pick
///   the right inbound-side adapter.
/// - `on_upgrade` -- (h1 only) the hyper future that resolves once
///   both endpoints have committed to the upgrade.  None for h2/h3,
///   whose upgraded stream comes from the body channels.
///
/// Note: `OnUpgrade` is a one-shot future and not `Clone`, so we
/// hold it behind `Arc<Mutex<Option<...>>>` -- the handler `take()`s
/// it on dispatch.  `http::Extensions` requires the stored type be
/// `Clone + Send + Sync + 'static`, which the Arc satisfies.
#[derive(Clone)]
pub struct UpgradeRequest {
    pub protocol: HeaderValue,
    pub inbound: InboundProtocol,
    pub on_upgrade: Arc<Mutex<Option<OnUpgrade>>>,
    /// `Sec-WebSocket-Key` captured off the inbound h1 request.
    /// Carried so the cross-protocol bridge (h1 -> h2/h3) can
    /// compute the matching `Sec-WebSocket-Accept` to send back on
    /// the synthesised 101 -- h2/h3 WebSocket per RFC 8441 §5.1
    /// elides the Key/Accept round-trip on the upstream side.
    pub ws_key: Option<HeaderValue>,
}

/// Source-side protocol of an upgrade request.  The dispatcher uses
/// this to pick the matching inbound-side `UpgradedStream` adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundProtocol {
    /// HTTP/1.1 with `Connection: upgrade; Upgrade: X`.
    H1,
    /// HTTP/2 with `:method CONNECT` + `:protocol X` (RFC 8441).
    H2,
    /// HTTP/3 with the same extended CONNECT shape (RFC 9220).
    H3,
}

/// Inspect an incoming h1 request: if it carries `Connection:
/// upgrade` with a non-empty `Upgrade:` header, snip the upgrade
/// future off via `hyper::upgrade::on(&mut req)` and return the
/// marker.  No-op otherwise.
///
/// MUST be called *before* the request body is mapped through
/// `boxed_unsync` -- once the original `Incoming` is consumed the
/// upgrade affordance disappears.
pub fn detect_h1_upgrade<B>(
    req: &mut Request<B>,
) -> Option<UpgradeRequest>
where
    OnUpgrade: From<hyper::upgrade::OnUpgrade>,
{
    if !connection_has_upgrade(req.headers().get(CONNECTION)?) {
        return None;
    }
    let protocol = req.headers().get(UPGRADE)?.clone();
    if protocol.as_bytes().is_empty() {
        return None;
    }
    let ws_key = req
        .headers()
        .get(hyper::header::SEC_WEBSOCKET_KEY)
        .cloned();
    let on_upgrade = hyper::upgrade::on(req);
    Some(UpgradeRequest {
        protocol,
        inbound: InboundProtocol::H1,
        on_upgrade: Arc::new(Mutex::new(Some(on_upgrade))),
        ws_key,
    })
}

/// Inspect an incoming h2 request for RFC 8441 extended CONNECT.
/// hyper surfaces the `:protocol` pseudo-header as
/// `Request::extensions().get::<hyper::ext::Protocol>()` when the
/// server was built with `enable_connect_protocol()`.
pub fn detect_h2_upgrade<B>(
    req: &mut Request<B>,
) -> Option<UpgradeRequest> {
    if req.method() != Method::CONNECT {
        return None;
    }
    let proto = req.extensions().get::<hyper::ext::Protocol>()?;
    let hv = HeaderValue::from_bytes(proto.as_str().as_bytes()).ok()?;
    let on_upgrade = hyper::upgrade::on(req);
    Some(UpgradeRequest {
        protocol: hv,
        inbound: InboundProtocol::H2,
        on_upgrade: Arc::new(Mutex::new(Some(on_upgrade))),
        ws_key: None,
    })
}

/// True iff a `Connection:` header value lists an `upgrade` token
/// (case-insensitive).  Connection-options are a comma-separated
/// list per RFC 9110 §7.6.1.
fn connection_has_upgrade(v: &HeaderValue) -> bool {
    let Ok(s) = v.to_str() else { return false };
    s.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
}

// -- Outbound h1 tunnel opener -------------------------------------

/// Open an h1 upgrade tunnel to a byte-stream upstream and return
/// the upstream's response head + the post-upgrade byte stream.
///
/// Bypasses the hyper-util Legacy Client connection pool: a
/// connection that just performed a 101 handoff is dedicated to the
/// tunnel and must never return to the pool.  We connect a fresh
/// TCP/Unix socket per call, hand it to `hyper::client::conn::http1`
/// configured with `with_upgrades()`, send the request once, and
/// pluck the upgraded stream out via `hyper::upgrade::on()`.
///
/// `upstream` is the proxy-handler URI (`http://host:port` or
/// `unix:/path`); TLS / `https://` upstreams are handled in a later
/// commit alongside the H2 origination path.
pub async fn open_h1_upstream_tunnel<B>(
    upstream: &hyper::Uri,
    req: hyper::Request<B>,
) -> anyhow::Result<(hyper::http::response::Parts, BoxedUpgradedStream)>
where
    B: hyper::body::Body + Unpin + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use anyhow::{Context, anyhow, bail};
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;

    let scheme = upstream.scheme_str().unwrap_or("http");
    let io: Box<dyn UpgradedStream> = match scheme {
        "http" => {
            let host = upstream.host().ok_or_else(|| {
                anyhow!("upgrade upstream missing host: {upstream}")
            })?;
            let port = upstream.port_u16().unwrap_or(80);
            Box::new(
                tokio::net::TcpStream::connect((host, port))
                    .await
                    .with_context(|| {
                        format!(
                            "connect upgrade upstream {host}:{port}"
                        )
                    })?,
            )
        }
        #[cfg(unix)]
        "unix" => {
            let path = upstream.path();
            Box::new(
                tokio::net::UnixStream::connect(path)
                    .await
                    .with_context(|| {
                        format!("connect upgrade upstream unix:{path}")
                    })?,
            )
        }
        s => bail!(
            "h1 upgrade tunnel: scheme `{s}://` is not yet supported \
             on the upgrade path (TLS / h2 follow up in #29)"
        ),
    };

    // `with_upgrades()` arms the connection task to keep driving
    // the underlying socket through the upgrade handoff; without
    // it the Connection future returns once the body of the 101
    // response is exhausted (which it is immediately) and the
    // socket gets dropped before `upgrade::on()` can wake.
    let (mut sender, conn) =
        http1::handshake(TokioIo::new(io)).await.context(
            "h1 client handshake for upgrade",
        )?;
    let conn_task = tokio::spawn(conn.with_upgrades());

    let mut resp = sender
        .send_request(req)
        .await
        .context("sending upgrade request to upstream")?;
    let status = resp.status();
    if status != hyper::StatusCode::SWITCHING_PROTOCOLS {
        // Non-101 means the upstream declined the upgrade.  The
        // connection task will close on its own; we drop the
        // upgrade affordance and surface the upstream's actual
        // response (status + headers) so the caller can mirror it
        // to the inbound client unchanged.
        drop(conn_task);
        let (parts, _) = resp.into_parts();
        // Empty body upgraded stream -- never used since the caller
        // checks status first.  A zero-length duplex stands in.
        let (_, never) = tokio::io::duplex(0);
        return Ok((parts, Box::new(never)));
    }
    let upgraded = hyper::upgrade::on(&mut resp)
        .await
        .map_err(|e| anyhow!("upstream upgrade handoff: {e}"))?;
    drop(sender); // ensure the conn task can finalise
    // The connection task drives the IO until the upgrade is
    // delivered; once we hold the `Upgraded`, the task is done
    // and we can drop it.  Detach -- it'll resolve to Ok(()).
    drop(conn_task);
    let (parts, _) = resp.into_parts();
    Ok((parts, h1_upgraded(upgraded)))
}

/// Open an h2 prior-knowledge upgrade tunnel against a plaintext
/// HTTP upstream.  Sends `:method CONNECT` + `:protocol <X>` (RFC
/// 8441), expects `200 OK`, and pulls the bidirectional byte
/// stream out via `hyper::upgrade::on()` on the response (h2's
/// CONNECT stream is surfaced through the same upgrade affordance
/// h1 uses for 101 handoffs).
pub async fn open_h2c_upstream_tunnel<B>(
    upstream: &hyper::Uri,
    mut req: hyper::Request<B>,
    protocol: &hyper::header::HeaderValue,
) -> anyhow::Result<(hyper::http::response::Parts, BoxedUpgradedStream)>
where
    B: hyper::body::Body + Unpin + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use anyhow::{Context, anyhow, bail};
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let scheme = upstream.scheme_str().unwrap_or("http");
    if scheme != "http" {
        bail!(
            "h2c upgrade tunnel: scheme `{scheme}://` is not valid; \
             use http:// for prior-knowledge h2 (TLS+h2 ALPN \
             follow-up)"
        );
    }
    let host = upstream
        .host()
        .ok_or_else(|| anyhow!("upstream missing host: {upstream}"))?;
    let port = upstream.port_u16().unwrap_or(80);
    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .with_context(|| {
            format!("connect h2c upgrade upstream {host}:{port}")
        })?;

    let (mut sender, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tcp))
        .await
        .context("h2c client handshake for upgrade")?;
    let _conn_task = tokio::spawn(conn);

    // Rewrite the request shape for h2 extended CONNECT:
    //   * `:method CONNECT`
    //   * `:protocol <X>` via the hyper::ext::Protocol extension
    //   * `:authority` from the upstream URI
    *req.method_mut() = hyper::Method::CONNECT;
    let proto_str = protocol.to_str().map_err(|_| {
        anyhow!("protocol header is not ASCII: {protocol:?}")
    })?;
    req.extensions_mut().insert(hyper::ext::Protocol::from_static(
        // `Protocol::from_static` requires a `&'static str` -- leak
        // the small protocol token once per tunnel.  The leak is
        // bounded by the (small) set of distinct upgrade protocols
        // an operator's clients use.
        Box::leak(proto_str.to_owned().into_boxed_str()),
    ));
    // hyper's h2 client requires the request URI to carry an
    // authority for CONNECT.  Reuse the upstream's.
    if let Some(authority) = upstream.authority() {
        let mut new_uri_parts = req.uri().clone().into_parts();
        new_uri_parts.authority = Some(authority.clone());
        new_uri_parts.scheme =
            Some(hyper::http::uri::Scheme::HTTP);
        if new_uri_parts.path_and_query.is_none() {
            new_uri_parts.path_and_query = Some(
                hyper::http::uri::PathAndQuery::from_static("/"),
            );
        }
        if let Ok(new_uri) =
            hyper::Uri::from_parts(new_uri_parts)
        {
            *req.uri_mut() = new_uri;
        }
    }

    let mut resp = sender
        .send_request(req)
        .await
        .context("sending h2c upgrade request to upstream")?;
    let status = resp.status();
    if status != hyper::StatusCode::OK {
        // h2 CONNECT success is 200, not 101.  Anything else means
        // the upstream declined; mirror its head back to the
        // caller without trying to upgrade.
        let (parts, _) = resp.into_parts();
        let (_, never) = tokio::io::duplex(0);
        return Ok((parts, Box::new(never)));
    }
    let upgraded = hyper::upgrade::on(&mut resp)
        .await
        .map_err(|e| anyhow!("h2c upstream upgrade handoff: {e}"))?;
    let (parts, _) = resp.into_parts();
    Ok((parts, h1_upgraded(upgraded)))
}

// -- H3 adapter ----------------------------------------------------
//
// h3::server::RequestStream / h3::client::RequestStream both expose
// async `recv_data` / `send_data` rather than poll-based AsyncRead /
// AsyncWrite, and the underlying h3-quinn types don't implement
// tokio's traits.  We bridge with a driver task that owns the
// split halves and forwards bytes through a tokio duplex; the
// adapter the bidi pump sees is just a `tokio::io::duplex` half.
//
// ## Known limitation: h3 generic extended CONNECT
//
// h3 0.0.8 (the latest release as of this writing) only accepts
// `:protocol` values of `webtransport` and `connect-udp`.  Arbitrary
// protocols -- notably `websocket` per RFC 9220 -- are rejected at
// the pseudo-header parser.  Until a future h3 crate version
// supports generic extended CONNECT, the h3 cells of the upgrade
// matrix (h3 inbound + h3 outbound) are blocked on upstream.
//
// The adapter machinery below is correct in shape and will start
// working as soon as h3 surfaces arbitrary `:protocol` values --
// no further hypershunt work needed beyond a `cargo update` and an
// inbound detection arm in `listener/quic.rs`.

use bytes::Bytes;

/// Spawn the driver task that bridges an h3 RequestStream into a
/// tokio duplex byte stream.  Returns the duplex half the bidi
/// pump consumes; the other duplex half lives inside the driver.
///
/// Generic over the h3 RequestStream type so a single helper covers
/// both the server's `RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>`
/// and the client's matching type.  The split halves are passed in
/// so callers can split a server `RequestStream` into its send and
/// recv parts.
pub fn h3_upgraded_from_split<S, R>(
    mut send: S,
    mut recv: R,
) -> BoxedUpgradedStream
where
    S: H3SendData + Send + 'static,
    R: H3RecvData + Send + 'static,
{
    // 64 KiB matches the buffer size on the byte-stream proxy
    // path.  A single QUIC datagram fits comfortably.
    let (adapter_io, mut driver_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut write_buf = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                // Upstream (or downstream) -> client: bytes from the
                // h3 RequestStream's recv half go into the duplex,
                // where the pump reads them as AsyncRead.
                res = recv.recv_data_owned() => match res {
                    Ok(Some(chunk)) => {
                        if driver_io.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        // End of inbound stream; shut down write
                        // half of the duplex so the pump sees EOF.
                        let _ = driver_io.shutdown().await;
                        // Keep the loop alive to drain pending
                        // outbound writes until the other side
                        // closes too.
                        let mut drain_buf = vec![0u8; 16 * 1024];
                        while let Ok(n) =
                            driver_io.read(&mut drain_buf).await
                        {
                            if n == 0 { break; }
                            if send.send_data_bytes(
                                Bytes::copy_from_slice(&drain_buf[..n]),
                            ).await.is_err() {
                                break;
                            }
                        }
                        let _ = send.finish_stream().await;
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("h3 upgrade: recv error: {e:?}");
                        break;
                    }
                },
                // Client -> upstream: bytes the pump wrote into the
                // duplex get framed into `send_data` calls.
                n = driver_io.read(&mut write_buf) => match n {
                    Ok(0) => {
                        let _ = send.finish_stream().await;
                        break;
                    }
                    Ok(n) => {
                        if send.send_data_bytes(
                            Bytes::copy_from_slice(&write_buf[..n]),
                        ).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    });
    Box::new(adapter_io)
}

/// Trait the h3 send half of a `RequestStream` satisfies.  We
/// abstract over the concrete h3 type so a single helper covers
/// both server (`h3_quinn::SendStream<Bytes>`) and client (same)
/// shapes without exposing `h3::*` types in the public API.
#[async_trait::async_trait]
pub trait H3SendData {
    async fn send_data_bytes(
        &mut self,
        bytes: Bytes,
    ) -> Result<(), anyhow::Error>;
    async fn finish_stream(&mut self) -> Result<(), anyhow::Error>;
}

/// Trait the h3 recv half of a `RequestStream` satisfies.
#[async_trait::async_trait]
pub trait H3RecvData {
    /// Returns `Ok(Some(buf))` for a frame, `Ok(None)` for EOF.
    async fn recv_data_owned(
        &mut self,
    ) -> Result<Option<Bytes>, anyhow::Error>;
}

// -- H1 adapter ----------------------------------------------------

/// Wrap a `hyper::upgrade::Upgraded` (the post-101 byte stream that
/// hyper hands back on both the server and client sides of an h1
/// `Upgrade:` exchange) as an `UpgradedStream`.
///
/// `hyper::upgrade::Upgraded` implements hyper's own IO traits;
/// `hyper_util::rt::TokioIo` is the conventional shim that bridges
/// those to tokio's `AsyncRead` / `AsyncWrite`.
pub fn h1_upgraded(
    upgraded: hyper::upgrade::Upgraded,
) -> BoxedUpgradedStream {
    Box::new(hyper_util::rt::TokioIo::new(upgraded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `pump` should drive bytes both ways between two duplex
    /// pipes until one side closes.  We use `tokio::io::duplex`
    /// pairs so the test stays fully in-process: a→b's reader gets
    /// what client a wrote, and b→a's reader gets what client b
    /// wrote.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_round_trips_bytes_both_ways_renamed() {
        let (a_inner, a_outer) = tokio::io::duplex(64);
        let (b_inner, b_outer) = tokio::io::duplex(64);
        let bidi = tokio::spawn(pump(
            Box::new(a_inner),
            Box::new(b_inner),
        ));
        let writer = tokio::spawn({
            let mut a = a_outer;
            let mut b = b_outer;
            async move {
                a.write_all(b"hello-from-a").await.unwrap();
                a.shutdown().await.unwrap();
                let mut got = Vec::new();
                b.read_to_end(&mut got).await.unwrap();
                b.write_all(b"reply-from-b").await.unwrap();
                b.shutdown().await.unwrap();
                got
            }
        });
        let from_a_seen_by_b = writer.await.unwrap();
        assert_eq!(from_a_seen_by_b, b"hello-from-a");
        let _ = bidi.await.unwrap();
    }

    /// End-to-end h1↔h1 WebSocket round-trip through hypershunt's
    /// reverse proxy.  Stands up:
    ///   * a tokio-tungstenite echo server (the backend)
    ///   * an hypershunt `TestServer` with a `proxy` location pointing
    ///     at the backend
    ///   * a tokio-tungstenite client connecting through hypershunt
    /// Sends a text frame, expects the echo back, then closes
    /// cleanly.  Pins the inbound detection + outbound h1 tunnel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn websocket_h1_round_trip_through_proxy() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{
            accept_async, connect_async,
            tungstenite::protocol::Message,
        };

        // -- 1. Echo backend --------------------------------------
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut ws =
                        accept_async(sock).await.unwrap();
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_text() || msg.is_binary() {
                            ws.send(msg).await.unwrap();
                        } else if msg.is_close() {
                            break;
                        }
                    }
                });
            }
        });

        // -- 2. hypershunt test server proxying to the backend ---------
        let template = format!(
            r#"
            listener "tcp://{{addr}}" {{ }}
            vhost "example.com" {{
                location "/" {{
                    proxy {{ upstream "http://{backend_addr}" }}
                }}
            }}
            "#,
        );
        let srv = crate::test::TestServer::start(&template).await;
        let hypershunt_addr = srv.addr;

        // -- 3. WebSocket client through hypershunt --------------------
        let url = format!("ws://{hypershunt_addr}/echo");
        let (mut ws, response) =
            connect_async(&url).await.expect("ws connect");
        assert_eq!(response.status(), 101);

        ws.send(Message::text("ping")).await.unwrap();
        let reply = ws.next().await.expect("got reply").unwrap();
        assert_eq!(reply.into_text().unwrap().as_str(), "ping");

        ws.close(None).await.unwrap();
    }

    /// h1 inbound -> h2c outbound, end-to-end through the frame-mask
    /// translator (issue #35).  The h1 WebSocket client masks its
    /// frames (RFC 6455 §5.3); the h2 backend speaks the unmasked
    /// RFC 8441 §5.5 convention.  The bridge unmasks client->server
    /// frames on the way out and byte-pumps the (already unmasked)
    /// server->client frames back, so the tungstenite client -- which
    /// rejects masked server frames -- sees a clean echo.  Before the
    /// translator landed this round-trip failed with
    /// `MaskedFrameFromServer`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn h1_inbound_to_h2c_outbound_round_trip() {
        use bytes::Bytes;
        use http_body_util::{BodyExt as _, Empty};
        use hyper::body::Incoming;
        use hyper::server::conn::http2;
        use hyper::service::service_fn;
        use hyper::{Method, Request, Response};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use std::convert::Infallible;
        use tokio::net::TcpListener;

        // h2 prior-knowledge echo backend.  Accepts CONNECT +
        // :protocol, returns 200, then echoes the upgraded stream.
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = backend.accept().await {
                let svc = service_fn(|mut req: Request<Incoming>| async move {
                    if req.method() != Method::CONNECT
                        || req
                            .extensions()
                            .get::<hyper::ext::Protocol>()
                            .is_none()
                    {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(400)
                                .body(
                                    Empty::<Bytes>::new()
                                        .map_err(|_| {
                                            std::io::Error::other("never")
                                        })
                                        .boxed_unsync(),
                                )
                                .unwrap(),
                        );
                    }
                    let upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        let Ok(upgraded) = upgrade.await else {
                            return;
                        };
                        use tokio::io::{
                            AsyncReadExt, AsyncWriteExt,
                        };
                        let mut io =
                            hyper_util::rt::TokioIo::new(upgraded);
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match io.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if io
                                        .write_all(&buf[..n])
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                    Ok(Response::builder()
                        .status(200)
                        .body(
                            Empty::<Bytes>::new()
                                .map_err(|_| {
                                    std::io::Error::other("never")
                                })
                                .boxed_unsync(),
                        )
                        .unwrap())
                });
                tokio::spawn(async move {
                    let mut builder =
                        http2::Builder::new(TokioExecutor::new());
                    builder.enable_connect_protocol();
                    let _ = builder
                        .serve_connection(TokioIo::new(sock), svc)
                        .await;
                });
            }
        });

        // hypershunt test server with scheme=h2c on the upstream.
        let template = format!(
            r#"
            listener "tcp://{{addr}}" {{ }}
            vhost "example.com" {{
                location "/" {{
                    proxy scheme="h2c" {{
                        upstream "http://{backend_addr}"
                    }}
                }}
            }}
            "#,
        );
        let srv = crate::test::TestServer::start(&template).await;
        let hypershunt_addr = srv.addr;

        // h1 WebSocket client through hypershunt.
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::{
            connect_async, tungstenite::protocol::Message,
        };
        let url = format!("ws://{hypershunt_addr}/echo");
        let (mut ws, response) =
            connect_async(&url).await.expect("ws connect");
        assert_eq!(response.status(), 101);
        ws.send(Message::text("cross-proto-ping")).await.unwrap();
        let reply = ws.next().await.expect("got reply").unwrap();
        assert_eq!(
            reply.into_text().unwrap().as_str(),
            "cross-proto-ping"
        );
        ws.close(None).await.unwrap();
    }

    /// h1 inbound -> h2c outbound against an h2 backend that performs
    /// *real* WebSocket framing (not a blind byte echo): it parses the
    /// inbound frame, asserts the MASK bit is clear -- proving the
    /// bridge stripped the RFC 6455 client mask before forwarding to
    /// the RFC 8441 backend -- and replies with a freshly framed
    /// `verified:<payload>` text frame.  A byte-pump regression would
    /// surface here as the backend seeing a masked frame (and the
    /// reply changing to `MASKED:...`), or the tungstenite client
    /// rejecting a masked server frame.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn h1_to_h2c_backend_frames_arrive_unmasked() {
        use bytes::Bytes;
        use http_body_util::{BodyExt as _, Empty};
        use hyper::body::Incoming;
        use hyper::server::conn::http2;
        use hyper::service::service_fn;
        use hyper::{Method, Request, Response};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use std::convert::Infallible;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = backend.accept().await {
                let svc = service_fn(|mut req: Request<Incoming>| async move {
                    if req.method() != Method::CONNECT
                        || req
                            .extensions()
                            .get::<hyper::ext::Protocol>()
                            .is_none()
                    {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(400)
                                .body(
                                    Empty::<Bytes>::new()
                                        .map_err(|_| {
                                            std::io::Error::other("never")
                                        })
                                        .boxed_unsync(),
                                )
                                .unwrap(),
                        );
                    }
                    let upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        let Ok(upgraded) = upgrade.await else {
                            return;
                        };
                        let mut io =
                            hyper_util::rt::TokioIo::new(upgraded);
                        // Read until a full frame is buffered, then
                        // parse it with the same codec the bridge uses.
                        let mut acc = Vec::new();
                        let mut buf = vec![0u8; 4096];
                        let header = loop {
                            if let Some(h) =
                                super::ws::parse_header(&acc).unwrap()
                            {
                                let end =
                                    h.header_len + h.payload_len as usize;
                                if acc.len() >= end {
                                    break h;
                                }
                            }
                            match io.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => acc.extend_from_slice(&buf[..n]),
                            }
                        };
                        let payload = &acc[header.header_len
                            ..header.header_len
                                + header.payload_len as usize];
                        // RFC 8441 §5.5: an h2 WS endpoint must never
                        // see a masked client frame.
                        let reply_text = if header.masked {
                            format!(
                                "MASKED:{}",
                                String::from_utf8_lossy(payload)
                            )
                        } else {
                            format!(
                                "verified:{}",
                                String::from_utf8_lossy(payload)
                            )
                        };
                        // Frame the reply as an unmasked server text
                        // frame (FIN + opcode 0x1).
                        let mut out = Vec::new();
                        super::ws::emit_header(
                            &mut out,
                            0x81,
                            reply_text.len() as u64,
                            None,
                        );
                        out.extend_from_slice(reply_text.as_bytes());
                        let _ = io.write_all(&out).await;
                        let _ = io.flush().await;
                    });
                    Ok(Response::builder()
                        .status(200)
                        .body(
                            Empty::<Bytes>::new()
                                .map_err(|_| {
                                    std::io::Error::other("never")
                                })
                                .boxed_unsync(),
                        )
                        .unwrap())
                });
                tokio::spawn(async move {
                    let mut builder =
                        http2::Builder::new(TokioExecutor::new());
                    builder.enable_connect_protocol();
                    let _ = builder
                        .serve_connection(TokioIo::new(sock), svc)
                        .await;
                });
            }
        });

        let template = format!(
            r#"
            listener "tcp://{{addr}}" {{ }}
            vhost "example.com" {{
                location "/" {{
                    proxy scheme="h2c" {{
                        upstream "http://{backend_addr}"
                    }}
                }}
            }}
            "#,
        );
        let srv = crate::test::TestServer::start(&template).await;
        let hypershunt_addr = srv.addr;

        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::{
            connect_async, tungstenite::protocol::Message,
        };
        let url = format!("ws://{hypershunt_addr}/echo");
        let (mut ws, response) =
            connect_async(&url).await.expect("ws connect");
        assert_eq!(response.status(), 101);
        ws.send(Message::text("payload-42")).await.unwrap();
        let reply = ws.next().await.expect("got reply").unwrap();
        assert_eq!(
            reply.into_text().unwrap().as_str(),
            "verified:payload-42",
            "backend must have seen an unmasked frame"
        );
        ws.close(None).await.unwrap();
    }
}
