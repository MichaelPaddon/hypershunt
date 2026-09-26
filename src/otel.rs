//! OpenTelemetry (OTLP) span export.
//!
//! Built only when the operator writes a `server { tracing { ... } }`
//! block.  Spans are produced by ordinary `tracing` spans elsewhere in
//! the server; this module owns the exporter, the sampler, and the W3C
//! trace-context plumbing that carries a trace across to upstreams.
//!
//! Transport is OTLP over HTTP/protobuf (collector port 4318 by
//! convention).  The HTTP client is the same hyper + rustls stack the
//! rest of the server uses, so no second TLS implementation is linked
//! in for the sake of the exporter.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use opentelemetry::global;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::TracerProvider as _;
use hyper::header::HeaderMap;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use opentelemetry_http::HttpClient;
use opentelemetry_http::hyper::HyperClient;
use opentelemetry_http::{HeaderExtractor, HeaderInjector};
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider, Tracer};

use crate::config::TracingConfig;

/// Longest we let the exporter block process exit while flushing.
/// A collector that has gone away must not hold the server open.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether an inbound `traceparent` may be continued.  Process-global
/// rather than carried on `AppState`: tracing is configured once at
/// startup (SIGHUP does not rebuild the exporter), and the request
/// path would otherwise thread a single bool through every call site.
static TRUST_INCOMING: AtomicBool = AtomicBool::new(false);

/// Whether span export is configured at all.  Read on the hot path to
/// skip work that only matters when someone is collecting.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// True when a `tracing` block was configured and the exporter built.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// True when an inbound `traceparent` should be continued rather than
/// discarded.  Always false when tracing is disabled.
pub fn trust_incoming() -> bool {
    TRUST_INCOMING.load(Ordering::Relaxed)
}

/// Debug rendering of the `tracing` block that built the exporter.
/// SIGHUP cannot rebuild an exporter, so the reload path compares
/// against this to tell the operator a restart is needed.
static FINGERPRINT: OnceLock<String> = OnceLock::new();

/// Fingerprint of the active tracing config; empty when disabled.
pub fn fingerprint() -> &'static str {
    FINGERPRINT.get().map(String::as_str).unwrap_or("")
}

/// Fingerprint the config the same way, for comparison against
/// [`fingerprint`].
pub fn fingerprint_of(cfg: Option<&TracingConfig>) -> String {
    cfg.map(|c| format!("{c:?}")).unwrap_or_default()
}

/// Owns the tracer provider.  Dropping it flushes whatever spans are
/// still batched, which is why `main` holds it until after the final
/// shutdown log line: the `?` early-return paths get the same flush
/// as an orderly exit.
pub struct OtelGuard {
    provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown_with_timeout(SHUTDOWN_TIMEOUT) {
            // The subscriber may already be tearing down, so this is
            // best-effort reporting of a best-effort flush.
            tracing::warn!(error = %e, "otel: span flush on shutdown failed");
        }
    }
}


/// The batch processor exports from a dedicated OS thread, which has
/// no tokio runtime of its own, and hyper needs one for its timers and
/// its I/O driver.  This wrapper hands each export back to the
/// server's runtime and waits for the result.
#[derive(Debug)]
struct RuntimeClient {
    inner: HyperClient<HttpsConnector<HttpConnector>>,
    handle: tokio::runtime::Handle,
}

#[async_trait::async_trait]
impl HttpClient for RuntimeClient {
    async fn send_bytes(
        &self,
        request: hyper::http::Request<bytes::Bytes>,
    ) -> Result<
        hyper::http::Response<bytes::Bytes>,
        opentelemetry_http::HttpError,
    > {
        let inner = self.inner.clone();
        self.handle
            .spawn(async move { inner.send_bytes(request).await })
            .await
            .map_err(|e| Box::new(e) as opentelemetry_http::HttpError)?
    }
}

/// Build the exporter and tracer provider described by `cfg`.
///
/// Returns the guard (hold it for the process lifetime) and a tracer
/// for `tracing_opentelemetry::layer().with_tracer(...)`.
pub fn init(cfg: &TracingConfig) -> anyhow::Result<(OtelGuard, Tracer)> {
    let headers: HashMap<String, String> =
        cfg.headers.iter().cloned().collect();

    // webpki roots: the collector is usually a local plaintext hop, but
    // a SaaS endpoint needs a trust anchor and we don't want to depend
    // on the host store being populated in a container.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = RuntimeClient {
        inner: HyperClient::new(
            https,
            Duration::from_secs(cfg.timeout_secs),
            None,
        ),
        handle: tokio::runtime::Handle::current(),
    };

    let exporter = SpanExporter::builder()
        .with_http()
        .with_http_client(client)
        .with_endpoint(&cfg.endpoint)
        .with_headers(headers)
        .with_timeout(Duration::from_secs(cfg.timeout_secs))
        .build()
        .map_err(|e| anyhow!("{e}"))
        .context("building the OTLP span exporter")?;

    let resource = Resource::builder()
        .with_service_name(cfg.service_name.clone())
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build();

    // Parent-based: a request that arrives already sampled stays
    // sampled, so a trace is never half-recorded.  The ratio only
    // decides traces that start here.
    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
        cfg.sample_ratio,
    )));

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer("hypershunt");
    global::set_text_map_propagator(TraceContextPropagator::new());
    let _ = FINGERPRINT.set(fingerprint_of(Some(cfg)));
    TRUST_INCOMING.store(cfg.trust_incoming, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Relaxed);

    Ok((OtelGuard { provider }, tracer))
}

/// Read W3C trace context from inbound request headers.
///
/// A malformed or absent `traceparent` yields an empty context, which
/// makes the request the root of a new trace.
pub fn extract(headers: &HeaderMap) -> opentelemetry::Context {
    TraceContextPropagator::new().extract(&HeaderExtractor(headers))
}

/// Write W3C trace context into an outbound request's headers.
///
/// Any inbound `traceparent` / `tracestate` is replaced: what we
/// forward must describe *our* span, not the client's claim about it.
pub fn inject(cx: &opentelemetry::Context, headers: &mut HeaderMap) {
    headers.remove("traceparent");
    headers.remove("tracestate");
    TraceContextPropagator::new()
        .inject_context(cx, &mut HeaderInjector(headers));
}

/// Inject the *currently active* span's context into an outbound
/// request.  A no-op when tracing is off or the active span has no
/// exported context, which also leaves any client-supplied
/// `traceparent` alone: with no collector configured hypershunt stays
/// a transparent hop.
pub fn inject_current(headers: &mut HeaderMap) {
    if !enabled() {
        return;
    }
    use opentelemetry::trace::TraceContextExt as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let cx = tracing::Span::current().context();
    if cx.span().span_context().is_valid() {
        inject(&cx, headers);
    }
}

/// Test scaffolding: a live tracer whose spans are discarded.  Tests
/// elsewhere in the crate need a *valid, sampled* span context to
/// prove that context is propagated; they don't need the spans to go
/// anywhere.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::trace::{SpanData, SpanExporter};

    #[derive(Debug)]
    struct NullExporter;

    impl SpanExporter for NullExporter {
        async fn export(&self, _batch: Vec<SpanData>) -> OTelSdkResult {
            Ok(())
        }
    }

    /// Install a tracing subscriber with an OTel layer for the current
    /// thread, marking tracing enabled for the duration.  Returns the
    /// guard; drop it to restore the previous subscriber.
    pub(crate) fn with_tracing<T>(f: impl FnOnce() -> T) -> T {
        use tracing_subscriber::layer::SubscriberExt as _;

        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(NullExporter)
            .with_sampler(Sampler::AlwaysOn)
            .build();
        let tracer = provider.tracer("test");
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer));

        let prev_enabled = ENABLED.swap(true, Ordering::Relaxed);
        let out = tracing::subscriber::with_default(subscriber, f);
        ENABLED.store(prev_enabled, Ordering::Relaxed);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceContextExt as _;

    // A well-formed traceparent must survive extract -> inject
    // unchanged in trace id, which is what makes one trace span two
    // services.
    #[test]
    fn round_trips_trace_context() {
        let mut inbound = HeaderMap::new();
        inbound.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .expect("static traceparent parses"),
        );

        let cx = extract(&inbound);
        let trace_id = cx.span().span_context().trace_id();

        let mut outbound = HeaderMap::new();
        inject(&cx, &mut outbound);

        let forwarded = outbound
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent injected");
        assert!(
            forwarded.contains(&trace_id.to_string()),
            "forwarded {forwarded:?} lost the trace id"
        );
    }

    // A client can send anything; garbage must not poison the trace,
    // and must not be forwarded verbatim either.
    #[test]
    fn malformed_traceparent_is_dropped() {
        let mut inbound = HeaderMap::new();
        inbound.insert(
            "traceparent",
            "not-a-traceparent".parse().expect("static value parses"),
        );

        let cx = extract(&inbound);
        assert!(
            !cx.span().span_context().is_valid(),
            "garbage traceparent produced a usable span context"
        );

        let mut outbound = inbound.clone();
        inject(&cx, &mut outbound);
        assert_ne!(
            outbound.get("traceparent").and_then(|v| v.to_str().ok()),
            Some("not-a-traceparent"),
            "client-supplied traceparent was forwarded unchanged"
        );
    }

    #[test]
    fn inject_current_is_inert_when_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .expect("static traceparent parses"),
        );
        inject_current(&mut headers);
        assert_eq!(
            headers.get("traceparent").and_then(|v| v.to_str().ok()),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
    }

    // Under an active span the client's claim is replaced by ours.
    #[test]
    fn inject_current_replaces_client_value() {
        testing::with_tracing(|| {
            let span = tracing::info_span!("t");
            let _e = span.enter();
            let mut headers = HeaderMap::new();
            headers.insert(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                    .parse()
                    .expect("static traceparent parses"),
            );
            inject_current(&mut headers);
            let got = headers
                .get("traceparent")
                .and_then(|v| v.to_str().ok())
                .expect("traceparent injected");
            assert_ne!(
                got,
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "client-supplied traceparent survived injection"
            );
        });
    }
}
