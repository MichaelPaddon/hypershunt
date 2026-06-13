// DNS-01 challenge plumbing for ACME.
//
// The `DnsProvider` trait fronts whatever back-end the operator has
// configured: an acme-dns server, the Cloudflare REST API, AWS
// Route 53 via the SDK, or a hand-rolled exec hook.  Each provider
// is responsible for installing and removing a TXT record under
// `_acme-challenge.<domain>` so the CA's resolver can validate.
//
// All providers are async + object-safe (`async_trait`) so the
// challenge dispatch in `RealProvisioner` can hold an `Arc<dyn
// DnsProvider>` without caring which back-end is in use.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::Duration;

use crate::config::DnsProviderConfig;

/// Async, object-safe trait every DNS-01 provider must implement.
/// `fqdn` is the full name of the TXT record (including the
/// `_acme-challenge.` prefix); `value` is the base64url SHA-256
/// digest of the ACME key authorization.
///
/// Implementations should return success only after the provider's
/// public API has accepted the change; hypershunt waits for DNS
/// propagation separately before telling the ACME server to
/// validate.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn set_txt(&self, fqdn: &str, value: &str) -> Result<()>;
    async fn clear_txt(&self, fqdn: &str, value: &str) -> Result<()>;
}

/// Construct a `DnsProvider` from its config-time description.
/// The mapping is exhaustive over `DnsProviderConfig`; Route53 is
/// only present when the binary was built with `--features
/// dns-route53` -- otherwise we return a parse-time error so
/// operators get a clear "rebuild with the feature" message.
pub fn build(cfg: &DnsProviderConfig) -> Result<Arc<dyn DnsProvider>> {
    match cfg {
        DnsProviderConfig::AcmeDns {
            api_url,
            username,
            password,
            subdomain,
        } => Ok(Arc::new(AcmeDnsProvider {
            api_url: api_url.clone(),
            username: username.clone(),
            password: password.clone(),
            subdomain: subdomain.clone(),
        })),
        DnsProviderConfig::Cloudflare { zone_id, api_token } => {
            Ok(Arc::new(CloudflareProvider {
                zone_id: zone_id.clone(),
                api_token: api_token.clone(),
            }))
        }
        DnsProviderConfig::Exec { program, args } => {
            Ok(Arc::new(ExecProvider {
                program: program.clone(),
                args: args.clone(),
            }))
        }
        #[cfg(feature = "dns-route53")]
        DnsProviderConfig::Route53 { hosted_zone_id } => Ok(Arc::new(
            Route53Provider::new(hosted_zone_id.clone())?,
        )),
        #[cfg(not(feature = "dns-route53"))]
        DnsProviderConfig::Route53 { .. } => Err(anyhow!(
            "dns-provider \"route53\" is unavailable in this build; \
             rebuild with `cargo build --features dns-route53`"
        )),
    }
}

/// Build a shared hyper-util HTTPS client for the REST providers.
/// rustls + webpki roots so we trust the same CAs as the rest of
/// the binary.  Tokio executor and HTTP/1.1 are enough for these
/// short request/response pairs.
fn https_client() -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
> {
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

// ---------------------------------------------------------------
// acme-dns: HTTP POST to /update with X-Api-User / X-Api-Key.  The
// CNAME indirection means we always publish under the operator's
// allocated `subdomain`, regardless of the requested FQDN; the CA's
// resolver follows the CNAME at validation time.
// ---------------------------------------------------------------

#[derive(Debug)]
struct AcmeDnsProvider {
    api_url: String,
    username: String,
    password: String,
    subdomain: String,
}

#[async_trait]
impl DnsProvider for AcmeDnsProvider {
    async fn set_txt(&self, _fqdn: &str, value: &str) -> Result<()> {
        let url = format!("{}/update", self.api_url.trim_end_matches('/'));
        let body = format!(
            r#"{{"subdomain":"{}","txt":"{}"}}"#,
            self.subdomain, value
        );
        let req = hyper::Request::builder()
            .method("POST")
            .uri(url)
            .header("X-Api-User", &self.username)
            .header("X-Api-Key", &self.password)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .context("building acme-dns update request")?;
        let resp = https_client()
            .request(req)
            .await
            .context("acme-dns /update")?;
        if !resp.status().is_success() {
            return Err(anyhow!("acme-dns /update returned {}", resp.status()));
        }
        Ok(())
    }

    async fn clear_txt(&self, _fqdn: &str, _value: &str) -> Result<()> {
        // acme-dns rotates the stored TXT on the next set, so an
        // explicit clear isn't required -- and isn't exposed by the
        // API.  Operators routinely rely on the next challenge to
        // overwrite the previous value.
        Ok(())
    }
}

// ---------------------------------------------------------------
// Cloudflare: REST API v4.  We create a TXT record on set and look
// it up by content on clear so the right record is deleted (a zone
// may carry multiple _acme-challenge entries for parallel orders).
// ---------------------------------------------------------------

#[derive(Debug)]
struct CloudflareProvider {
    zone_id: String,
    api_token: String,
}

impl CloudflareProvider {
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_token)
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn set_txt(&self, fqdn: &str, value: &str) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );
        let body = serde_json::json!({
            "type": "TXT",
            "name": fqdn.trim_end_matches('.'),
            "content": value,
            "ttl": 60,
        })
        .to_string();
        let req = hyper::Request::builder()
            .method("POST")
            .uri(url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .context("building Cloudflare create-record request")?;
        let resp = https_client()
            .request(req)
            .await
            .context("Cloudflare POST dns_records")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body =
                resp.into_body().collect().await.map(|b| b.to_bytes());
            return Err(anyhow!(
                "Cloudflare create-record returned {}: {}",
                status,
                body.map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default()
            ));
        }
        Ok(())
    }

    async fn clear_txt(&self, fqdn: &str, value: &str) -> Result<()> {
        let name = fqdn.trim_end_matches('.');
        // Find the record by (type, name, content) so we don't wipe
        // unrelated TXT entries.
        let list_url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records\
             ?type=TXT&name={}&content={}",
            self.zone_id,
            urlencoding(name),
            urlencoding(value)
        );
        let req = hyper::Request::builder()
            .method("GET")
            .uri(list_url)
            .header("Authorization", self.auth_header())
            .body(Full::new(Bytes::new()))
            .context("building Cloudflare list-records request")?;
        let resp = https_client()
            .request(req)
            .await
            .context("Cloudflare GET dns_records")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "Cloudflare list-records returned {}",
                resp.status()
            ));
        }
        let body =
            resp.into_body().collect().await?.to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body)
            .context("parsing Cloudflare list-records response")?;
        let id = v
            .get("result")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first())
            .and_then(|r| r.get("id"))
            .and_then(|i| i.as_str())
            .map(|s| s.to_owned());
        let id = match id {
            Some(i) => i,
            // Already gone; nothing to do.
            None => return Ok(()),
        };
        let del_url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.zone_id, id
        );
        let req = hyper::Request::builder()
            .method("DELETE")
            .uri(del_url)
            .header("Authorization", self.auth_header())
            .body(Full::new(Bytes::new()))
            .context("building Cloudflare delete-record request")?;
        let resp = https_client()
            .request(req)
            .await
            .context("Cloudflare DELETE dns_records")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "Cloudflare delete-record returned {}",
                resp.status()
            ));
        }
        Ok(())
    }
}

/// Minimal URL-encoder for the handful of characters that show up
/// in TXT record values (`+`, `=`, `/`) and FQDNs.  Adequate for the
/// Cloudflare query-string above; not a general-purpose encoder.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------
// Exec: run an operator-supplied program with action / fqdn / value
// as environment variables.  Always available; useful for any DNS
// provider not built into the binary.
// ---------------------------------------------------------------

#[derive(Debug)]
struct ExecProvider {
    program: String,
    args: Vec<String>,
}

impl ExecProvider {
    async fn run(&self, action: &str, fqdn: &str, value: &str) -> Result<()> {
        let status = tokio::process::Command::new(&self.program)
            .args(&self.args)
            .env("HYPERSHUNT_DNS_ACTION", action)
            .env("HYPERSHUNT_DNS_FQDN", fqdn)
            .env("HYPERSHUNT_DNS_VALUE", value)
            .status()
            .await
            .with_context(|| {
                format!("spawning DNS exec hook '{}'", self.program)
            })?;
        if !status.success() {
            return Err(anyhow!(
                "DNS exec hook '{}' exited with status {status}",
                self.program
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for ExecProvider {
    async fn set_txt(&self, fqdn: &str, value: &str) -> Result<()> {
        self.run("set", fqdn, value).await
    }
    async fn clear_txt(&self, fqdn: &str, value: &str) -> Result<()> {
        self.run("clear", fqdn, value).await
    }
}

// ---------------------------------------------------------------
// Route 53.  Uses the AWS SDK; gated behind the dns-route53 Cargo
// feature so the default binary stays slim.
// ---------------------------------------------------------------

#[cfg(feature = "dns-route53")]
struct Route53Provider {
    hosted_zone_id: String,
    client: tokio::sync::OnceCell<aws_sdk_route53::Client>,
}

#[cfg(feature = "dns-route53")]
impl Route53Provider {
    fn new(hosted_zone_id: String) -> Result<Self> {
        Ok(Route53Provider {
            hosted_zone_id,
            client: tokio::sync::OnceCell::new(),
        })
    }

    async fn client(&self) -> &aws_sdk_route53::Client {
        self.client
            .get_or_init(|| async {
                // Route 53 is a global service; the SDK still needs
                // a region but us-east-1 is the conventional choice
                // for the global endpoint.
                let cfg = aws_config::defaults(
                    aws_config::BehaviorVersion::latest(),
                )
                .region(aws_config::Region::new("us-east-1"))
                .load()
                .await;
                aws_sdk_route53::Client::new(&cfg)
            })
            .await
    }

    async fn change(
        &self,
        action: aws_sdk_route53::types::ChangeAction,
        fqdn: &str,
        value: &str,
    ) -> Result<()> {
        use aws_sdk_route53::types::{
            Change, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
        };
        let rec = ResourceRecord::builder()
            // TXT record values must be wrapped in literal quotes.
            .value(format!("\"{value}\""))
            .build()
            .map_err(|e| anyhow!("building Route53 record: {e}"))?;
        let rrs = ResourceRecordSet::builder()
            .name(fqdn)
            .r#type(RrType::Txt)
            .ttl(60)
            .resource_records(rec)
            .build()
            .map_err(|e| anyhow!("building Route53 rrset: {e}"))?;
        let change = Change::builder()
            .action(action)
            .resource_record_set(rrs)
            .build()
            .map_err(|e| anyhow!("building Route53 change: {e}"))?;
        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| anyhow!("building Route53 batch: {e}"))?;
        self.client()
            .await
            .change_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| anyhow!("Route53 change failed: {e}"))?;
        Ok(())
    }
}

#[cfg(feature = "dns-route53")]
#[async_trait]
impl DnsProvider for Route53Provider {
    async fn set_txt(&self, fqdn: &str, value: &str) -> Result<()> {
        self.change(
            aws_sdk_route53::types::ChangeAction::Upsert,
            fqdn,
            value,
        )
        .await
    }
    async fn clear_txt(&self, fqdn: &str, value: &str) -> Result<()> {
        self.change(
            aws_sdk_route53::types::ChangeAction::Delete,
            fqdn,
            value,
        )
        .await
    }
}

/// Default propagation wait after `set_txt` succeeds.  RFC 8555
/// recommends that clients wait until the resolver they expect the
/// ACME server to use has caught up; in practice 30 s covers most
/// public providers, and operators can override by extending the
/// `retry_interval` on the tls-acme block when their DNS is slower.
pub const DEFAULT_PROPAGATION_WAIT: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_preserves_safe_chars() {
        assert_eq!(urlencoding("abcXYZ09-_.~"), "abcXYZ09-_.~");
    }

    #[test]
    fn urlencoding_escapes_unsafe_chars() {
        // Base64URL TXT values use `+`, `=`, `/` (or `_`, `-` in
        // the URL-safe variant); make sure unsafe chars are escaped.
        assert_eq!(urlencoding("a+b=c/d"), "a%2Bb%3Dc%2Fd");
    }

    #[test]
    fn build_acme_dns_provider_succeeds() {
        let cfg = DnsProviderConfig::AcmeDns {
            api_url: "https://acme-dns.example/".into(),
            username: "u".into(),
            password: "p".into(),
            subdomain: "abc".into(),
        };
        assert!(build(&cfg).is_ok());
    }

    #[test]
    fn build_cloudflare_provider_succeeds() {
        let cfg = DnsProviderConfig::Cloudflare {
            zone_id: "Z".into(),
            api_token: "T".into(),
        };
        assert!(build(&cfg).is_ok());
    }

    #[test]
    fn build_exec_provider_succeeds() {
        let cfg = DnsProviderConfig::Exec {
            program: "/bin/true".into(),
            args: vec![],
        };
        assert!(build(&cfg).is_ok());
    }

    #[test]
    fn cloudflare_auth_header_is_bearer_token() {
        let p = CloudflareProvider {
            zone_id: "Z".into(),
            api_token: "tok-123".into(),
        };
        assert_eq!(p.auth_header(), "Bearer tok-123");
    }

    /// Write an executable stub script that records its action and
    /// environment to `out`, exiting with `code`.
    fn stub_hook(dir: &std::path::Path, code: i32) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        let script = dir.join("hook.sh");
        let out = dir.join("out.txt");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 echo \"$1 $HYPERSHUNT_DNS_ACTION \
                 $HYPERSHUNT_DNS_FQDN $HYPERSHUNT_DNS_VALUE\" \
                 >> {}\nexit {}\n",
                out.display(),
                code
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &script,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        script.display().to_string()
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir()
            .join(format!("hypershunt-dns-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn exec_provider_passes_action_env_and_args() {
        let dir = temp_dir("ok");
        let p = ExecProvider {
            program: stub_hook(&dir, 0),
            args: vec!["positional".into()],
        };
        p.set_txt("_acme-challenge.example.com", "v1").await.unwrap();
        p.clear_txt("_acme-challenge.example.com", "v1").await.unwrap();
        let out =
            std::fs::read_to_string(dir.join("out.txt")).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            [
                "positional set _acme-challenge.example.com v1",
                "positional clear _acme-challenge.example.com v1",
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn exec_provider_maps_nonzero_exit_to_error() {
        let dir = temp_dir("fail");
        let p = ExecProvider { program: stub_hook(&dir, 3), args: vec![] };
        let err = p
            .set_txt("f", "v")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("exited with status"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn exec_provider_maps_missing_program_to_spawn_error() {
        let p = ExecProvider {
            program: "/no/such/hypershunt-hook".into(),
            args: vec![],
        };
        let err = p
            .set_txt("f", "v")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("spawning DNS exec hook"), "got: {err}");
    }

    #[cfg(not(feature = "dns-route53"))]
    #[test]
    fn build_route53_without_feature_errors() {
        let cfg = DnsProviderConfig::Route53 {
            hosted_zone_id: "Z".into(),
        };
        // dyn DnsProvider is not Debug, so unwrap_err can't print
        // it; pattern-match instead.
        let err = match build(&cfg) {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("dns-route53"), "got: {err}");
    }
}
