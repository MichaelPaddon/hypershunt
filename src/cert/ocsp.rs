// OCSP stapling for TLS listeners.
//
// Responsibility split:
//   - `extract_ocsp_url`  parses the leaf cert's Authority Information
//     Access extension and returns the first OCSP responder URL.
//   - `build_request`     hashes the issuer name and SPKI under SHA-1
//     and serialises an OCSPRequest (no nonce, no signature) DER blob
//     ready to POST.
//   - `parse_response`    decodes the responder's reply into a staple
//     and the validity window so the refresh task knows when to come
//     back.
//   - `fetch_staple`      runs the full flow (parse, build, HTTP POST,
//     parse) and returns the staple bytes + nextUpdate.
//   - `spawn_refresh_task` runs as a tokio task per CertSource and
//     republishes the latest staple through the CertPair watch channel
//     so the existing `VhostAlpnMap` rebuild path picks it up.
//
// Failure semantics throughout: best-effort.  An unreachable responder
// or a malformed response logs WARN, increments
// `ocsp_refresh_failures`, and leaves the listener serving without a
// staple.  A cert with no OCSP responder URL is NOT a failure: the
// semantic of `ocsp=#true` is "staple when available", and CAs have
// been dropping OCSP since the CA/B Forum made it optional in 2023
// (Let's Encrypt stopped publishing responder URLs in May 2025), so
// URL-less certs are the normal case for ACME.  Stapling is an
// optimisation; it must never break TLS or spam the logs.

use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rasn::types::{Integer, OctetString};
use rasn_ocsp::{
    BasicOcspResponse, CertId, OcspRequest, OcspResponse, OcspResponseStatus,
    Request, TbsRequest,
};
use rasn_pkix::{
    AuthorityInfoAccessSyntax, Certificate, Extension, GeneralName,
};
use sha1::{Digest, Sha1};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::OcspConfig;
use crate::metrics::Metrics;
use crate::cert::tls::{CertPair, clone_key};

/// OID 1.3.6.1.5.5.7.1.1 -- id-pe-authorityInfoAccess.
const OID_AIA: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
/// OID 1.3.6.1.5.5.7.48.1 -- id-ad-ocsp (the AIA accessMethod that
/// identifies an OCSP responder URL).
const OID_AD_OCSP: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
/// OID 1.3.6.1.5.5.7.48.1.1 -- id-pkix-ocsp-basic; the only response
/// type rustls actually staples.  Other responses are valid OCSP but
/// not stapleable, so we reject them as if the fetch had failed.
const OID_OCSP_BASIC: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];
/// OID 1.3.14.3.2.26 -- SHA-1 hash, the only algorithm every public
/// responder is required to accept for CertID hashing.  RFC 5019.
const OID_SHA1: &[u32] = &[1, 3, 14, 3, 2, 26];

/// Parsed result of a successful staple fetch.
#[derive(Debug)]
pub struct Staple {
    /// Raw DER OCSPResponse bytes, passed to rustls verbatim.
    pub der: Vec<u8>,
    /// When the responder says this staple becomes invalid; the
    /// refresh task uses this to schedule the next fetch.  `None`
    /// when the responder omits `nextUpdate` (rare but legal).
    pub next_update: Option<SystemTime>,
}

/// Extract the first OCSP responder URL from a leaf certificate's
/// AIA extension.  Returns `None` when the cert has no AIA extension,
/// when AIA has no OCSP entry, or when the URL is not a URI form.
pub fn extract_ocsp_url(leaf_der: &[u8]) -> Result<Option<String>> {
    let cert: Certificate = rasn::der::decode(leaf_der)
        .map_err(|e| anyhow!("decoding leaf cert: {e}"))?;
    let exts = match cert.tbs_certificate.extensions {
        Some(e) => e,
        None => return Ok(None),
    };
    let aia_ext = exts.iter().find(|e: &&Extension| {
        e.extn_id.as_ref() == OID_AIA
    });
    let aia_ext = match aia_ext {
        Some(e) => e,
        None => return Ok(None),
    };
    let aia: AuthorityInfoAccessSyntax =
        rasn::der::decode(aia_ext.extn_value.as_ref())
            .map_err(|e| anyhow!("decoding AIA extension: {e}"))?;
    for ad in &aia {
        if ad.access_method.as_ref() != OID_AD_OCSP {
            continue;
        }
        if let GeneralName::Uri(uri) = &ad.access_location {
            return Ok(Some(uri.to_string()));
        }
    }
    Ok(None)
}

/// Build the OCSPRequest body to POST for a leaf cert signed by
/// `issuer`.  Uses SHA-1 for the issuer name/key hashes; per RFC 5019
/// this is the lowest-common-denominator that every public responder
/// is required to support.
pub fn build_request(
    leaf_der: &[u8],
    issuer_der: &[u8],
) -> Result<Vec<u8>> {
    let leaf: Certificate = rasn::der::decode(leaf_der)
        .map_err(|e| anyhow!("decoding leaf cert: {e}"))?;
    let issuer: Certificate = rasn::der::decode(issuer_der)
        .map_err(|e| anyhow!("decoding issuer cert: {e}"))?;

    // Issuer Name hash: SHA-1 over the DER encoding of the *leaf's*
    // issuer name.  This must equal the DER of the issuer's subject;
    // we use the leaf's view because that is the bytes the responder
    // expects.
    let issuer_name_der =
        rasn::der::encode(&leaf.tbs_certificate.issuer)
            .map_err(|e| anyhow!("re-encoding issuer name: {e}"))?;
    let issuer_name_hash = sha1(&issuer_name_der);

    // Issuer Key hash: SHA-1 over the raw bytes of the SPKI's BIT
    // STRING value (the public key itself, no tag/length prefix).
    let spki_bits =
        &issuer.tbs_certificate.subject_public_key_info.subject_public_key;
    let mut spki_bytes = Vec::with_capacity(spki_bits.len() / 8 + 1);
    for chunk in spki_bits.as_raw_slice() {
        spki_bytes.push(*chunk);
    }
    let issuer_key_hash = sha1(&spki_bytes);

    let cert_id = CertId {
        hash_algorithm: rasn_pkix::AlgorithmIdentifier {
            algorithm: oid(OID_SHA1),
            parameters: Some(rasn::types::Any::new(vec![0x05, 0x00])),
        },
        issuer_name_hash: OctetString::from(issuer_name_hash.to_vec()),
        issuer_key_hash: OctetString::from(issuer_key_hash.to_vec()),
        serial_number: leaf.tbs_certificate.serial_number.clone(),
    };

    let req = OcspRequest {
        tbs_request: TbsRequest {
            version: Integer::from(0u8),
            requestor_name: None,
            request_list: vec![Request {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };
    rasn::der::encode(&req)
        .map_err(|e| anyhow!("encoding OCSPRequest: {e}"))
}

/// Parse an OCSPResponse DER blob into a `Staple` + a sanity check
/// that the response is `successful` and carries a `BasicOcspResponse`.
/// Returns an error if the responder said `tryLater` / `unauthorized`
/// or wrapped a non-basic response type that rustls cannot staple.
pub fn parse_response(der: &[u8]) -> Result<Staple> {
    let resp: OcspResponse = rasn::der::decode(der)
        .map_err(|e| anyhow!("decoding OCSPResponse: {e}"))?;
    if resp.status != OcspResponseStatus::Successful {
        return Err(anyhow!(
            "OCSP responder returned non-success status {:?}",
            resp.status
        ));
    }
    let body = resp.bytes.ok_or_else(|| {
        anyhow!("OCSP successful response carried no responseBytes")
    })?;
    if body.r#type.as_ref() != OID_OCSP_BASIC {
        return Err(anyhow!(
            "OCSP response is not id-pkix-ocsp-basic; cannot staple"
        ));
    }
    let basic: BasicOcspResponse = rasn::der::decode(body.response.as_ref())
        .map_err(|e| anyhow!("decoding BasicOCSPResponse: {e}"))?;
    let single = basic
        .tbs_response_data
        .responses
        .first()
        .ok_or_else(|| anyhow!("OCSP BasicResponse had no SingleResponse"))?;
    let next_update = single
        .next_update
        .as_ref()
        .map(chrono_to_systemtime);
    Ok(Staple { der: der.to_vec(), next_update })
}

/// One-shot OCSP fetch: build the request, POST it to the responder
/// at `url` over hyper, and parse the result.  Honors
/// `fetch_timeout_secs`.  The caller extracts the responder URL (see
/// `staple_source`) so that "this cert offers no OCSP" can be handled
/// upstream as a non-error.
pub async fn fetch_staple(
    url: &str,
    leaf_der: &[u8],
    issuer_der: &[u8],
    cfg: &OcspConfig,
) -> Result<Staple> {
    let body = build_request(leaf_der, issuer_der)?;
    let uri: hyper::Uri = url
        .parse()
        .with_context(|| format!("parsing OCSP URL '{url}'"))?;

    // Use the same TLS-capable hyper-util client shape as the rest of
    // the codebase.  Responders typically live on plain HTTP but some
    // CAs (notably Let's Encrypt's "OCSP responder") front them with
    // HTTPS, so the connector advertises both.
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri.clone())
        .header(hyper::header::CONTENT_TYPE, "application/ocsp-request")
        .header(hyper::header::ACCEPT, "application/ocsp-response")
        .body(Full::new(Bytes::from(body)))
        .context("building OCSP HTTP request")?;
    let timeout = Duration::from_secs(cfg.fetch_timeout_secs);
    let resp = tokio::time::timeout(timeout, client.request(req))
        .await
        .map_err(|_| anyhow!("OCSP HTTP request timed out"))?
        .with_context(|| format!("POST {uri}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "OCSP responder returned HTTP {}",
            resp.status()
        ));
    }
    let bytes = resp
        .into_body()
        .collect()
        .await
        .context("reading OCSP response body")?
        .to_bytes();
    parse_response(&bytes)
}

/// SHA-1 helper.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 20];
    a.copy_from_slice(&out);
    a
}

/// Construct an rasn ObjectIdentifier from a slice of arcs.
fn oid(arcs: &[u32]) -> rasn::types::ObjectIdentifier {
    rasn::types::ObjectIdentifier::new(arcs.to_vec()).unwrap()
}

/// Convert a chrono DateTime<Utc> (rasn's GeneralizedTime alias) into a
/// std::time::SystemTime.  Times before the unix epoch are clamped to
/// UNIX_EPOCH so the caller never observes a negative duration.
fn chrono_to_systemtime(
    gt: &chrono::DateTime<chrono::FixedOffset>,
) -> SystemTime {
    let secs = gt.timestamp();
    if secs <= 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    }
}

/// Cache path for a leaf cert's most-recent staple.  Keyed by the
/// SHA-256 of the leaf DER so file-cert and ACME-cert flows share a
/// single namespace under `<state_dir>/ocsp/`.
fn staple_cache_path(
    state_dir: &std::path::Path,
    leaf_der: &[u8],
) -> PathBuf {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(leaf_der);
    let digest = h.finalize();
    let mut name = String::with_capacity(64 + 4);
    for b in digest.iter() {
        use std::fmt::Write as _;
        let _ = write!(&mut name, "{b:02x}");
    }
    name.push_str(".der");
    state_dir.join("ocsp").join(name)
}

/// Whether a leaf certificate offers OCSP at all.  Distinguishes
/// "no responder URL" (the normal case for ACME certs since CAs
/// began dropping OCSP in 2025 — serve unstapled, not an error)
/// from a malformed certificate (a genuine failure).
#[derive(Debug, PartialEq)]
pub enum StapleSource {
    /// The cert names an OCSP responder; fetch from this URL.
    Url(String),
    /// The cert has no OCSP responder URL; stapling is simply not
    /// available for it.
    NotOffered,
}

/// Classify a leaf cert for the refresh task: responder URL,
/// not-offered, or parse error.
pub fn staple_source(leaf_der: &[u8]) -> Result<StapleSource> {
    Ok(match extract_ocsp_url(leaf_der)? {
        Some(url) => StapleSource::Url(url),
        None => StapleSource::NotOffered,
    })
}

/// Long-running task that fetches an OCSP staple, publishes it via
/// `cert_tx`, persists it to disk if a `state_dir` is configured, and
/// then refreshes shortly before the staple's `nextUpdate`.  The task
/// terminates only when the channel sender is closed.
pub fn spawn_refresh_task(
    label: String,
    cfg: OcspConfig,
    state_dir: Option<PathBuf>,
    cert_rx: tokio::sync::watch::Receiver<Arc<CertPair>>,
    cert_tx: Arc<ArcSwap<tokio::sync::watch::Sender<Arc<CertPair>>>>,
    metrics: Arc<Metrics>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    Some(crate::task::spawn_supervised("ocsp.refresh", async move {
        // Owned so we can advance its "seen" version each iteration.
        let mut cert_rx = cert_rx;
        let mut prior_leaf: Option<Vec<u8>> = None;
        loop {
            // borrow_and_update (not borrow) marks the current cert as
            // seen; otherwise this receiver's version stays frozen at
            // startup and, once the channel advances (a renewal), every
            // later changed() returns instantly, spinning the CPU.
            let pair = cert_rx.borrow_and_update().clone();
            // The cert that we'll be stapling for.  Recapture every
            // iteration so an ACME renewal swaps in seamlessly.
            let leaf_der = match pair.chain.first() {
                Some(c) => c.as_ref().to_vec(),
                None => {
                    tracing::warn!(
                        listener = %label,
                        "OCSP: empty cert chain; nothing to staple"
                    );
                    tokio::time::sleep(Duration::from_secs(
                        cfg.failure_backoff_secs,
                    ))
                    .await;
                    continue;
                }
            };
            // If the cert just rotated, drop the on-disk cache for the
            // previous leaf so we don't serve a stale staple if a
            // restart races against a fresh fetch.
            let leaf_changed = prior_leaf.as_ref() != Some(&leaf_der);
            if leaf_changed
                && prior_leaf.is_some()
                && let Some(sd) = &state_dir
            {
                let prev = prior_leaf.as_ref().expect("checked is_some");
                let _ = std::fs::remove_file(staple_cache_path(sd, prev));
            }
            prior_leaf = Some(leaf_der.clone());

            // "Staple when available": a cert without a responder URL
            // is served unstapled.  Log once per leaf, leave the
            // failure counter alone, and park until a renewal might
            // change the answer.  Only a malformed cert falls through
            // to the failure path below.
            let url = match staple_source(&leaf_der) {
                Ok(StapleSource::Url(url)) => url,
                Ok(StapleSource::NotOffered) => {
                    if leaf_changed {
                        tracing::info!(
                            listener = %label,
                            "OCSP: certificate has no responder URL; \
                             serving without a staple (normal for \
                             ACME CAs since 2025)"
                        );
                    }
                    let _ = cert_rx.changed().await;
                    continue;
                }
                Err(e) => {
                    metrics.ocsp_refresh_failures.fetch_add(
                        1,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    tracing::warn!(
                        listener = %label,
                        "OCSP: parsing certificate: {e:#}"
                    );
                    tokio::time::sleep(Duration::from_secs(
                        cfg.failure_backoff_secs,
                    ))
                    .await;
                    continue;
                }
            };

            // The cert offers OCSP, so a fetch needs the issuer cert
            // to hash into the request.  A chain without one is a
            // genuine misconfiguration (the URL is unusable), unlike
            // the self-signed case which is caught above as
            // NotOffered (self-signed certs carry no responder URL).
            let issuer_der = match pair.chain.get(1) {
                Some(c) => c.as_ref().to_vec(),
                None => {
                    tracing::warn!(
                        listener = %label,
                        "OCSP: cert names a responder but the chain \
                         has no issuer; cannot staple (chain length \
                         < 2)"
                    );
                    // Wait for a renewal that might bring an issuer.
                    let _ = cert_rx.changed().await;
                    continue;
                }
            };

            let next_delay = match fetch_staple(
                &url, &leaf_der, &issuer_der, &cfg,
            )
            .await
            {
                Ok(staple) => {
                    metrics
                        .ocsp_refreshes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Some(sd) = &state_dir {
                        let path = staple_cache_path(sd, &leaf_der);
                        if let Some(parent) = path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        if let Err(e) = std::fs::write(&path, &staple.der) {
                            tracing::warn!(
                                listener = %label,
                                "OCSP: writing staple cache {}: {e:#}",
                                path.display()
                            );
                        }
                    }
                    // Publish the staple by sending a fresh CertPair
                    // through the watch channel.  This triggers the
                    // existing renewal-watcher path that rebuilds
                    // VhostAlpnMap and (for QUIC) the ServerConfig.
                    let delay = schedule_next(&staple, &cfg);
                    let new_pair = Arc::new(CertPair {
                        chain: pair.chain.clone(),
                        key: clone_key(&pair.key),
                        // Preserve any TLS-ALPN-01 challenge store
                        // attached to the cert source; only the
                        // staple bytes are refreshed here.
                        alpn_store: pair.alpn_store.clone(),
                        ocsp: staple.der,
                    });
                    let tx = cert_tx.load();
                    if tx.send(new_pair).is_err() {
                        // No subscribers; nothing to do but log and
                        // exit gracefully.
                        tracing::debug!(
                            listener = %label,
                            "OCSP: no CertSource subscribers; refresh \
                             task exiting"
                        );
                        return;
                    }
                    delay
                }
                Err(e) => {
                    metrics.ocsp_refresh_failures.fetch_add(
                        1,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    tracing::warn!(
                        listener = %label,
                        "OCSP: fetch failed: {e:#}"
                    );
                    Duration::from_secs(cfg.failure_backoff_secs)
                }
            };
            tokio::time::sleep(next_delay).await;
        }
    }))
}

/// Pick a refresh delay halfway between now and the staple's
/// `nextUpdate`, but never less than `min_refresh_secs` (so a
/// long-lived staple still gets re-checked at the configured floor)
/// and never more than `nextUpdate - 5 minutes` so we always refresh
/// before the staple expires.
fn schedule_next(staple: &Staple, cfg: &OcspConfig) -> Duration {
    let min = Duration::from_secs(cfg.min_refresh_secs);
    let now = SystemTime::now();
    let next = match staple.next_update {
        Some(t) => t,
        None => return min,
    };
    let total = match next.duration_since(now) {
        Ok(d) => d,
        Err(_) => return Duration::from_secs(cfg.failure_backoff_secs),
    };
    // Aim for the midpoint; never let the staple expire by leaving
    // ourselves at least 5 minutes of headroom.
    let margin = Duration::from_secs(300);
    let half = total / 2;
    let cap = total.saturating_sub(margin);
    let chosen = half.min(cap);
    if chosen < min { min } else { chosen }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CA + leaf cert pair with an AIA OCSP URL, using rcgen.
    /// Returns (leaf DER, issuer DER) so tests can drive the codec
    /// helpers without a real responder.
    fn make_chain(ocsp_url: Option<&str>) -> (Vec<u8>, Vec<u8>) {
        use rcgen::{
            CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        };
        // CA
        let mut ca_params =
            CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca =
            IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "hypershunt-ocsp-test-CA");
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        let ca_kp = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, ca_kp);

        // Leaf
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example.com");
        if let Some(url) = ocsp_url {
            // rcgen exposes a custom-extension hook for AIA via
            // CustomExtension.  Emit a minimal AIA SEQUENCE containing
            // one AccessDescription { accessMethod=ocsp,
            // accessLocation=uri }.
            let aia = encode_aia_ocsp(url);
            let mut ext = rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                aia,
            );
            ext.set_criticality(false);
            leaf_params.custom_extensions.push(ext);
        }
        let leaf_kp = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
        (leaf.der().to_vec(), ca_cert.der().to_vec())
    }

    /// Hand-roll the DER for an AIA SEQUENCE OF (single entry, OCSP +
    /// URI form).  rcgen's CustomExtension only takes the raw extn
    /// bytes; we feed it the encoded value of AuthorityInfoAccessSyntax.
    fn encode_aia_ocsp(url: &str) -> Vec<u8> {
        use rasn::types::Ia5String;
        let aia: AuthorityInfoAccessSyntax =
            vec![rasn_pkix::AccessDescription {
                access_method: oid(OID_AD_OCSP),
                access_location: GeneralName::Uri(
                    Ia5String::try_from(url.as_bytes().to_vec()).unwrap(),
                ),
            }];
        rasn::der::encode(&aia).unwrap()
    }

    #[test]
    fn extract_ocsp_url_finds_aia_uri() {
        let (leaf, _) = make_chain(Some("http://ocsp.example.com/"));
        let url = extract_ocsp_url(&leaf).unwrap();
        assert_eq!(url.as_deref(), Some("http://ocsp.example.com/"));
    }

    #[test]
    fn extract_ocsp_url_returns_none_when_no_aia() {
        let (leaf, _) = make_chain(None);
        let url = extract_ocsp_url(&leaf).unwrap();
        assert!(url.is_none(), "expected no AIA, got {url:?}");
    }

    #[test]
    fn staple_source_classifies_url_cert() {
        let (leaf, _) = make_chain(Some("http://ocsp.example.com/"));
        assert_eq!(
            staple_source(&leaf).unwrap(),
            StapleSource::Url("http://ocsp.example.com/".into())
        );
    }

    #[test]
    fn staple_source_treats_missing_url_as_not_offered() {
        // "Staple when available": a cert with no responder URL is
        // NotOffered, not an error -- the normal case for ACME certs
        // since CAs began dropping OCSP.
        let (leaf, _) = make_chain(None);
        assert_eq!(
            staple_source(&leaf).unwrap(),
            StapleSource::NotOffered
        );
    }

    #[test]
    fn staple_source_errors_on_garbage_cert() {
        assert!(staple_source(b"not a certificate").is_err());
    }

    #[test]
    fn build_request_roundtrips_serial_and_url() {
        let (leaf, issuer) = make_chain(Some("http://r.example/"));
        let body = build_request(&leaf, &issuer).unwrap();
        // It at least round-trips: decoding succeeds and the request
        // list carries exactly one entry that names the SHA-1 algorithm.
        let req: OcspRequest = rasn::der::decode(&body).unwrap();
        assert_eq!(req.tbs_request.request_list.len(), 1);
        let cert_id = &req.tbs_request.request_list[0].req_cert;
        assert_eq!(cert_id.hash_algorithm.algorithm.as_ref(), OID_SHA1);
        assert_eq!(cert_id.issuer_name_hash.len(), 20);
        assert_eq!(cert_id.issuer_key_hash.len(), 20);
    }

    #[test]
    fn parse_response_rejects_non_basic() {
        // Build an OCSPResponse with status=successful but a fake
        // response OID that isn't id-pkix-ocsp-basic.  parse_response
        // must reject it -- rustls only knows how to staple basic
        // responses.
        let resp = OcspResponse {
            status: OcspResponseStatus::Successful,
            bytes: Some(rasn_ocsp::ResponseBytes {
                r#type: oid(&[1, 2, 3, 4]),
                response: OctetString::from(vec![0u8; 4]),
            }),
        };
        let der = rasn::der::encode(&resp).unwrap();
        let err = parse_response(&der).unwrap_err().to_string();
        assert!(
            err.contains("id-pkix-ocsp-basic"),
            "expected basic-response rejection, got: {err}"
        );
    }

    #[test]
    fn parse_response_rejects_try_later() {
        let resp = OcspResponse {
            status: OcspResponseStatus::TryLater,
            bytes: None,
        };
        let der = rasn::der::encode(&resp).unwrap();
        let err = parse_response(&der).unwrap_err().to_string();
        assert!(err.contains("non-success"), "got: {err}");
    }

    #[test]
    fn schedule_next_uses_floor_without_next_update() {
        let cfg = OcspConfig::default();
        let staple = Staple { der: vec![], next_update: None };
        assert_eq!(
            schedule_next(&staple, &cfg),
            Duration::from_secs(cfg.min_refresh_secs)
        );
    }

    #[test]
    fn schedule_next_backs_off_when_staple_expired() {
        let cfg = OcspConfig::default();
        let staple = Staple {
            der: vec![],
            next_update: Some(UNIX_EPOCH), // long past
        };
        assert_eq!(
            schedule_next(&staple, &cfg),
            Duration::from_secs(cfg.failure_backoff_secs)
        );
    }

    #[test]
    fn schedule_next_picks_midpoint_of_long_window() {
        let cfg = OcspConfig { min_refresh_secs: 60, ..Default::default() };
        let staple = Staple {
            der: vec![],
            next_update: Some(
                SystemTime::now() + Duration::from_secs(10_000),
            ),
        };
        let d = schedule_next(&staple, &cfg).as_secs();
        // Midpoint of ~10000s; allow slack for test runtime.
        assert!((4_990..=5_000).contains(&d), "got {d}");
    }

    #[test]
    fn schedule_next_leaves_expiry_headroom() {
        // 400s window: midpoint 200s would leave only 200s headroom;
        // the 5-minute margin caps the delay at ~100s instead.
        let cfg = OcspConfig { min_refresh_secs: 1, ..Default::default() };
        let staple = Staple {
            der: vec![],
            next_update: Some(
                SystemTime::now() + Duration::from_secs(400),
            ),
        };
        let d = schedule_next(&staple, &cfg).as_secs();
        assert!((90..=100).contains(&d), "got {d}");
    }

    #[test]
    fn schedule_next_never_drops_below_floor() {
        // Tiny window: cap is 0, but the configured floor wins.
        let cfg = OcspConfig::default(); // floor 3600
        let staple = Staple {
            der: vec![],
            next_update: Some(
                SystemTime::now() + Duration::from_secs(10),
            ),
        };
        assert_eq!(
            schedule_next(&staple, &cfg),
            Duration::from_secs(cfg.min_refresh_secs)
        );
    }

    #[test]
    fn chrono_to_systemtime_clamps_pre_epoch() {
        use chrono::TimeZone as _;
        let pre = chrono::FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(1960, 1, 1, 0, 0, 0)
            .unwrap();
        assert_eq!(chrono_to_systemtime(&pre), UNIX_EPOCH);
        let post = chrono::FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
            .unwrap();
        assert_eq!(
            chrono_to_systemtime(&post),
            UNIX_EPOCH + Duration::from_secs(post.timestamp() as u64)
        );
    }

    /// Wrap DER chains in a CertPair for refresh-task tests.
    fn test_pair(chain_der: Vec<Vec<u8>>) -> Arc<CertPair> {
        use rustls::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer,
        };
        let kp = rcgen::KeyPair::generate().unwrap();
        Arc::new(CertPair {
            chain: chain_der
                .into_iter()
                .map(|d| CertificateDer::from(d))
                .collect(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                kp.serialize_der(),
            )),
            alpn_store: None,
            ocsp: Vec::new(),
        })
    }

    /// Spawn the refresh task over `pair` and assert that after a
    /// settling delay it has neither recorded a failure nor fetched a
    /// staple — the quiet "park" contract for unstapleable certs.
    async fn assert_task_parks(pair: Arc<CertPair>) {
        let metrics = Arc::new(Metrics::new());
        let (tx, rx) = tokio::sync::watch::channel(pair.clone());
        let tx = Arc::new(ArcSwap::from_pointee(tx));
        let handle = spawn_refresh_task(
            "test".into(),
            OcspConfig::default(),
            None,
            rx,
            tx.clone(),
            metrics.clone(),
        )
        .expect("enabled config must spawn the task");

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            metrics
                .ocsp_refresh_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "parked task must not count failures"
        );
        assert_eq!(
            metrics
                .ocsp_refreshes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(!handle.is_finished(), "task must stay parked, not exit");

        // A renewal that still cannot staple re-parks quietly.
        tx.load().send(pair).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            metrics
                .ocsp_refresh_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        handle.abort();
    }

    #[tokio::test]
    async fn refresh_task_parks_on_cert_without_responder_url() {
        // Chain of two, but the leaf carries no AIA OCSP URL: the
        // staple-when-available semantics from the OCSP deprecation
        // work — serve unstapled, log once, touch no failure metric.
        let (leaf, issuer) = make_chain(None);
        assert_task_parks(test_pair(vec![leaf, issuer])).await;
    }

    #[tokio::test]
    async fn refresh_task_parks_on_self_signed_chain() {
        // Single-cert chain (self-signed): no issuer, no URL; same
        // quiet park.
        let (leaf, _) = make_chain(None);
        assert_task_parks(test_pair(vec![leaf])).await;
    }

    #[tokio::test]
    async fn refresh_task_not_spawned_when_disabled() {
        let cfg = OcspConfig { enabled: false, ..Default::default() };
        let (leaf, issuer) = make_chain(None);
        let pair = test_pair(vec![leaf, issuer]);
        let (tx, rx) = tokio::sync::watch::channel(pair);
        let tx = Arc::new(ArcSwap::from_pointee(tx));
        assert!(
            spawn_refresh_task(
                "test".into(),
                cfg,
                None,
                rx,
                tx,
                Arc::new(Metrics::new()),
            )
            .is_none()
        );
    }

    // Regression test for the busy-loop that pinned a CPU core after
    // the first ACME renewal: the refresh task re-borrowed the cert
    // with `borrow()` (which never advances the receiver's seen
    // version), so once the channel advanced every subsequent
    // changed() returned instantly.  Under the paused clock, virtual
    // time only auto-advances when the runtime is idle; a spinning
    // task keeps it busy forever, so the long sleep below would hang.
    // With the fix the task re-parks and the sleep returns at once.
    #[tokio::test(start_paused = true)]
    async fn refresh_task_reparks_after_renewal_without_spinning() {
        let metrics = Arc::new(Metrics::new());
        // Two distinct URL-less (NotOffered) certs, so the "renewal"
        // is a genuine version bump on the watch channel.
        let (leaf1, issuer1) = make_chain(None);
        let (leaf2, issuer2) = make_chain(None);
        let pair1 = test_pair(vec![leaf1, issuer1]);
        let pair2 = test_pair(vec![leaf2, issuer2]);

        let (tx, rx) = tokio::sync::watch::channel(pair1);
        let tx = Arc::new(ArcSwap::from_pointee(tx));
        let handle = spawn_refresh_task(
            "test".into(),
            OcspConfig::default(),
            None,
            rx,
            tx.clone(),
            metrics.clone(),
        )
        .expect("enabled config must spawn the task");

        // Let the task reach its first park on the initial cert.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Simulate the ACME renewal that triggered the incident.
        tx.load().send(pair2).unwrap();

        // If the task busy-loops, the runtime never goes idle and this
        // sleep can never auto-advance -> the test hangs (regression).
        // If it re-parks, virtual time jumps and the sleep returns.
        tokio::time::sleep(Duration::from_secs(3600)).await;

        assert!(
            !handle.is_finished(),
            "refresh task must stay parked, not exit"
        );
        assert_eq!(
            metrics
                .ocsp_refresh_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "re-parking on a URL-less cert must not count failures"
        );
        handle.abort();
    }

    #[test]
    fn staple_cache_path_is_stable_and_hashed() {
        let tmp = std::env::temp_dir();
        let p1 = staple_cache_path(&tmp, b"hello world");
        let p2 = staple_cache_path(&tmp, b"hello world");
        let p3 = staple_cache_path(&tmp, b"different");
        assert_eq!(p1, p2, "same input must hash to same path");
        assert_ne!(p1, p3, "different input must differ");
        assert!(
            p1.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(".der")
        );
    }
}
