// Test-only HTTP/2 prior-knowledge server that accepts a single
// RFC 8441 extended CONNECT (`:method CONNECT` + `:protocol <X>`),
// returns 200, and bidi-echoes the upgraded byte stream back to the
// client.  Used by the integration suite to drive hypershunt's
// h1<->h2c upgrade bridge against a real h2 backend.
//
// Usage:
//     h2c_connect_echo 127.0.0.1:9400
//
// Listens forever; one connection at a time is sufficient for the
// suite.  Exits on SIGINT/SIGTERM via tokio's default signal
// handling.

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9400".into());
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("h2c_connect_echo listening on {addr}");
    loop {
        let (sock, _) = listener.accept().await?;
        tokio::spawn(async move {
            let svc = service_fn(
                |mut req: Request<Incoming>| async move {
                    if req.method() != Method::CONNECT
                        || req
                            .extensions()
                            .get::<hyper::ext::Protocol>()
                            .is_none()
                    {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(400)
                                .body(empty_body())
                                .unwrap(),
                        );
                    }
                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        let Ok(u) = on_upgrade.await else { return };
                        let mut io = TokioIo::new(u);
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
                        .body(empty_body())
                        .unwrap())
                },
            );
            let mut builder = http2::Builder::new(TokioExecutor::new());
            builder.enable_connect_protocol();
            let _ = builder
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });
    }
}

fn empty_body() -> http_body_util::combinators::UnsyncBoxBody<
    Bytes,
    std::io::Error,
> {
    Empty::<Bytes>::new()
        .map_err(|_| std::io::Error::other("never"))
        .boxed_unsync()
}
