// Test-only gRPC-shaped backend: an HTTP/2 prior-knowledge (h2c)
// server that answers every request the way a gRPC service does --
// `content-type: application/grpc`, the request body echoed back,
// and the call's outcome in a `grpc-status` trailer rather than in
// the HTTP status line.
//
// It speaks the framing, not the protobuf: the suite only needs a
// backend that is unreachable over HTTP/1.1 and that answers with
// trailers, which is enough to prove hypershunt negotiated h2c and
// passed the trailers through.
//
// Usage:
//     grpc_echo 127.0.0.1:9500
//
// Listens forever.  Exits on SIGINT/SIGTERM via tokio's default
// signal handling.

use futures_util::stream;
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::env;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9500".into());
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("grpc_echo listening on {addr}");
    loop {
        let (sock, _) = listener.accept().await?;
        tokio::spawn(async move {
            let svc = service_fn(|req: Request<Incoming>| async move {
                // Echo the request body so the round trip is visible
                // to the caller; a real service would decode it.
                let echoed = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let mut trailers = HeaderMap::new();
                trailers.insert(
                    "grpc-status",
                    "0".parse().expect("digits are a valid header"),
                );
                let body = StreamBody::new(stream::iter(vec![
                    Ok::<_, std::io::Error>(Frame::data(echoed)),
                    Ok(Frame::trailers(trailers)),
                ]));
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("content-type", "application/grpc")
                        .body(body.boxed())
                        .expect("valid response"),
                )
            });
            let _ = http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });
    }
}
