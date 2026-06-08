// TLS-side config parsing: the single `tls "<kind>" key=... { ... }`
// node used on listeners and inside a top-level `certificate` body.
// OCSP, mTLS, ACME challenge selection, and DNS-01 providers all live
// here too.

use super::super::kdl::*;
use super::super::{
    CertificateDef, TlsConfig, TlsListenerConfig, TlsOptions, TlsVersion,
};
use super::node_line;
use ::kdl::KdlNode;
use anyhow::{Context, anyhow, bail};

// Property readers (local copy; the parent module's helpers are not
// re-exported into the submodule namespace).
fn prop_str(node: &KdlNode, key: &str) -> Option<String> {
    node.get(key).and_then(|e| e.as_string()).map(String::from)
}
fn prop_bool(node: &KdlNode, key: &str) -> Option<bool> {
    node.get(key).and_then(|e| e.as_bool())
}
fn prop_i64(node: &KdlNode, key: &str) -> Option<i64> {
    node.get(key).and_then(|e| e.as_integer()).map(|n| n as i64)
}

/// Listener-side TLS.  Looks for at most one `tls` child of the
/// listener block, reads its positional kind, and dispatches to the
/// kind-specific parser.
pub(crate) fn parse_listener_tls<'a, I: IntoIterator<Item = &'a KdlNode>>(
    children: I,
    src: &str,
    name: &str,
) -> anyhow::Result<Option<TlsListenerConfig>> {
    let mut tls_nodes: Vec<&KdlNode> = Vec::new();
    for child in children {
        if child.name().value() == "tls" {
            tls_nodes.push(child);
        }
    }
    let node = match tls_nodes.as_slice() {
        [] => return Ok(None),
        [n] => *n,
        [_, n2, ..] => {
            let line = node_line(src, n2);
            bail!("{name}:{line}: at most one 'tls' node per listener");
        }
    };
    Ok(Some(parse_tls_node(node, src, name, /* allow_ref */ true)?))
}

/// Parse a `tls "<kind>" ... { ... }` node.  `allow_ref` is `true`
/// when called for a listener (where `tls "ref" name="<name>"` is
/// allowed) and `false` when called for a `certificate` body (where
/// it isn't).
fn parse_tls_node(
    node: &KdlNode,
    src: &str,
    name: &str,
    allow_ref: bool,
) -> anyhow::Result<TlsListenerConfig> {
    let line = node_line(src, node);
    let kind = req_arg_str(node, 0).with_context(|| {
        format!(
            "{name}:{line}: 'tls' requires a positional kind argument \
             (\"files\", \"acme\", \"self-signed\", or \"ref\")"
        )
    })?;
    let cert = match kind.as_str() {
        "files" => {
            let cert = prop_str(node, "cert").ok_or_else(|| {
                anyhow!(
                    "{name}:{line}: tls \"files\" requires cert=\"...\" \
                     (PEM file path)"
                )
            })?;
            let key = prop_str(node, "key").ok_or_else(|| {
                anyhow!(
                    "{name}:{line}: tls \"files\" requires key=\"...\" \
                     (PEM file path)"
                )
            })?;
            TlsConfig::Files { cert, key }
        }
        "self-signed" => {
            // Self-signed accepts no kind-specific attributes; flag
            // any of the well-known foreign names explicitly (whether
            // they appear as properties or as children) so a
            // misplaced cert path doesn't get silently ignored.
            for forbidden in
                ["cert", "key", "name", "domain", "email", "staging"]
            {
                if node.get(forbidden).is_some() {
                    bail!(
                        "{name}:{line}: tls \"self-signed\" has no \
                         '{forbidden}' property"
                    );
                }
                let has_child = node
                    .children()
                    .map(|d| {
                        d.nodes()
                            .iter()
                            .any(|n| n.name().value() == forbidden)
                    })
                    .unwrap_or(false);
                if has_child {
                    bail!(
                        "{name}:{line}: tls \"self-signed\" has no \
                         '{forbidden}' attribute"
                    );
                }
            }
            TlsConfig::SelfSigned
        }
        "acme" => parse_tls_acme(node, src, name)?,
        "ref" => {
            if !allow_ref {
                bail!(
                    "{name}:{line}: tls \"ref\" is only valid on a \
                     listener; inside a 'certificate' body use \
                     \"files\", \"acme\", or \"self-signed\""
                );
            }
            let ref_name = prop_str(node, "name").ok_or_else(|| {
                anyhow!(
                    "{name}:{line}: tls \"ref\" requires name=\"<cert>\" \
                     pointing at a top-level certificate"
                )
            })?;
            TlsConfig::Ref(ref_name)
        }
        other => bail!(
            "{name}:{line}: unknown tls kind {other:?}; expected \
             \"files\", \"acme\", \"self-signed\", or \"ref\""
        ),
    };
    let options = parse_tls_options(node, src, name)?;
    let mtls = parse_mtls(node, src, name)?;
    let ocsp = parse_ocsp(node, src, name)?;
    Ok(TlsListenerConfig { cert, options, mtls, ocsp })
}

/// Parse the kind-specific properties for `tls "acme"`.  Domain list
/// is read from repeating `domain "..."` children; `dns-provider` is
/// the only structured child the block carries.
fn parse_tls_acme(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TlsConfig> {
    let line = node_line(src, node);
    let domains: Vec<String> = node
        .children()
        .map(|doc| {
            doc.nodes()
                .iter()
                .filter(|n| n.name().value() == "domain")
                .filter_map(|n| arg_str(n, 0))
                .collect()
        })
        .unwrap_or_default();
    if domains.is_empty() {
        bail!(
            "{name}:{line}: tls \"acme\" requires at least one \
             'domain \"...\"' child"
        );
    }
    let challenge = match prop_str(node, "challenge").as_deref() {
        None | Some("http-01") => crate::config::ChallengeKind::Http01,
        Some("dns-01") => crate::config::ChallengeKind::Dns01,
        Some("tls-alpn-01") => crate::config::ChallengeKind::TlsAlpn01,
        Some(other) => bail!(
            "{name}:{line}: unknown challenge {other:?}; \
             expected \"http-01\", \"dns-01\", or \"tls-alpn-01\""
        ),
    };
    let dns_provider = parse_dns_provider(node, src, name)?;
    if challenge == crate::config::ChallengeKind::Dns01
        && dns_provider.is_none()
    {
        bail!(
            "{name}:{line}: challenge \"dns-01\" requires a \
             'dns-provider' child"
        );
    }
    if challenge != crate::config::ChallengeKind::Dns01
        && dns_provider.is_some()
    {
        bail!(
            "{name}:{line}: 'dns-provider' is only valid with \
             challenge \"dns-01\""
        );
    }
    // Wildcards force DNS-01 (HTTP-01 / TLS-ALPN-01 can't validate
    // `*.foo`); fail fast at parse rather than at ACME-time.
    if challenge != crate::config::ChallengeKind::Dns01
        && domains.iter().any(|d| d.starts_with("*."))
    {
        bail!(
            "{name}:{line}: wildcard domain found but challenge is \
             '{}'; wildcards require challenge \"dns-01\"",
            match challenge {
                crate::config::ChallengeKind::Http01 => "http-01",
                crate::config::ChallengeKind::TlsAlpn01 => "tls-alpn-01",
                crate::config::ChallengeKind::Dns01 => unreachable!(),
            }
        );
    }
    Ok(TlsConfig::Acme {
        domains,
        name: prop_str(node, "name"),
        email: prop_str(node, "email"),
        staging: prop_bool(node, "staging").unwrap_or(false),
        server: prop_str(node, "server"),
        retry_interval_secs: prop_i64(node, "retry-interval")
            .map(|n| n as u64)
            .unwrap_or(3600),
        challenge,
        dns_provider,
    })
}

/// Parse the optional OCSP-stapling knobs on a `tls` node.  All four
/// knobs are properties on the node.  Returns the default config when
/// none are set.
fn parse_ocsp(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::OcspConfig> {
    let mut cfg = crate::config::OcspConfig::default();
    let line = node_line(src, node);
    if let Some(b) = prop_bool(node, "ocsp") {
        cfg.enabled = b;
    }
    if let Some(n) = prop_i64(node, "ocsp-timeout") {
        if n <= 0 {
            bail!("{name}:{line}: 'ocsp-timeout' must be positive");
        }
        cfg.fetch_timeout_secs = n as u64;
    }
    if let Some(n) = prop_i64(node, "ocsp-min-refresh") {
        if n <= 0 {
            bail!("{name}:{line}: 'ocsp-min-refresh' must be positive");
        }
        cfg.min_refresh_secs = n as u64;
    }
    if let Some(n) = prop_i64(node, "ocsp-failure-backoff") {
        if n <= 0 {
            bail!(
                "{name}:{line}: 'ocsp-failure-backoff' must be positive"
            );
        }
        cfg.failure_backoff_secs = n as u64;
    }
    Ok(cfg)
}

/// Parse the optional `mtls { ... }` child.  CAs and revocation lists
/// are read from repeating single-argument children; mode and refresh
/// are properties on the mtls node.
fn parse_mtls(
    parent: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<Option<crate::config::MtlsConfig>> {
    use crate::config::{MtlsConfig, MtlsMode};

    let Some(doc) = parent.children() else {
        return Ok(None);
    };
    let Some(node) =
        doc.nodes().iter().find(|n| n.name().value() == "mtls")
    else {
        return Ok(None);
    };
    let line = node_line(src, node);

    let cas: Vec<String> = node
        .children()
        .map(|d| {
            d.nodes()
                .iter()
                .filter(|n| n.name().value() == "ca")
                .filter_map(|n| arg_str(n, 0))
                .collect()
        })
        .unwrap_or_default();
    if cas.is_empty() {
        bail!(
            "{name}:{line}: 'mtls' requires at least one 'ca \"...\"' \
             child (trust anchor PEM file)"
        );
    }

    let mode = match prop_str(node, "mode")
        .as_deref()
        .unwrap_or("required")
    {
        "required" => MtlsMode::Required,
        "optional" => MtlsMode::Optional,
        other => bail!(
            "{name}:{line}: unknown mtls mode '{other}'; expected \
             'required' or 'optional'"
        ),
    };

    let crls: Vec<String> = node
        .children()
        .map(|d| {
            d.nodes()
                .iter()
                .filter(|n| n.name().value() == "revocation")
                .filter_map(|n| arg_str(n, 0))
                .collect()
        })
        .unwrap_or_default();

    let crl_refresh_secs = prop_i64(node, "refresh")
        .map(|n| {
            if n < 0 {
                bail!(
                    "{name}:{line}: mtls 'refresh' must be >= 0 (got {n})"
                );
            }
            Ok(n as u64)
        })
        .transpose()?
        .unwrap_or(0);

    Ok(Some(MtlsConfig { cas, mode, crls, crl_refresh_secs }))
}

/// Parse the optional `dns-provider "<kind>" key=... { arg "..." }`
/// child inside a `tls "acme"` block.
fn parse_dns_provider(
    parent: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<Option<crate::config::DnsProviderConfig>> {
    use crate::config::DnsProviderConfig;
    let children = match parent.children() {
        Some(d) => d.nodes(),
        None => return Ok(None),
    };
    let node = match children
        .iter()
        .find(|n| n.name().value() == "dns-provider")
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let line = node_line(src, node);
    let kind = req_arg_str(node, 0).with_context(|| {
        format!(
            "{name}:{line}: 'dns-provider' takes a kind argument \
             (\"acme-dns\", \"cloudflare\", \"route53\", or \"exec\")"
        )
    })?;
    let need = |k: &str| -> anyhow::Result<String> {
        prop_str(node, k).ok_or_else(|| {
            anyhow!(
                "{name}:{line}: dns-provider \"{kind}\" requires \
                 {k}=\"...\""
            )
        })
    };
    let cfg = match kind.as_str() {
        "acme-dns" => DnsProviderConfig::AcmeDns {
            api_url: need("api-url")?,
            username: need("username")?,
            password: need("password")?,
            subdomain: need("subdomain")?,
        },
        "cloudflare" => DnsProviderConfig::Cloudflare {
            zone_id: need("zone-id")?,
            api_token: need("api-token")?,
        },
        "route53" => DnsProviderConfig::Route53 {
            hosted_zone_id: need("hosted-zone-id")?,
        },
        "exec" => {
            let program = need("program")?;
            // `arg "..."` repeating single-argument children carry
            // the program's argv tail, one per child.
            let args = node
                .children()
                .map(|doc| {
                    doc.nodes()
                        .iter()
                        .filter(|n| n.name().value() == "arg")
                        .filter_map(|n| arg_str(n, 0))
                        .collect()
                })
                .unwrap_or_default();
            DnsProviderConfig::Exec { program, args }
        }
        other => bail!(
            "{name}:{line}: unknown dns-provider {other:?}; expected \
             \"acme-dns\", \"cloudflare\", \"route53\", or \"exec\""
        ),
    };
    Ok(Some(cfg))
}

/// Parse a top-level `certificate "<name>" { tls "<kind>" ... }` node.
///
/// The body holds exactly one `tls` child whose kind is one of
/// `"files"`, `"acme"`, `"self-signed"` (not `"ref"` -- a certificate
/// cannot reference itself).
pub(crate) fn parse_certificate(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<CertificateDef> {
    let line = node_line(src, node);
    let cert_name = req_arg_str(node, 0).with_context(|| {
        format!(
            "{name}:{line}: certificate requires a name as its first \
             argument"
        )
    })?;

    let mut tls_nodes: Vec<&KdlNode> = Vec::new();
    for child in node.children().map(|d| d.nodes()).unwrap_or_default() {
        if child.name().value() == "tls" {
            tls_nodes.push(child);
        }
    }
    let tls_node = match tls_nodes.as_slice() {
        [] => bail!(
            "{name}:{line}: certificate '{cert_name}' has no 'tls' \
             child; expected `tls \"files\" cert=... key=...`, \
             `tls \"acme\" ...`, or `tls \"self-signed\"`"
        ),
        [n] => *n,
        [_, n2, ..] => {
            let line = node_line(src, n2);
            bail!(
                "{name}:{line}: certificate '{cert_name}' has more \
                 than one 'tls' child; certificates carry one source"
            );
        }
    };
    let parsed = parse_tls_node(tls_node, src, name, /* allow_ref */ false)?;
    Ok(CertificateDef { name: cert_name, source: parsed.cert, line })
}

/// Parse the per-source / per-server TLS options block.
///
/// At server scope this is the `tls-options { ... }` node carrying the
/// global defaults; at listener scope these same options also live as
/// children of the `tls "<kind>"` node.  In both cases the option
/// children are `min-version` (one), `cipher` (repeated), and the OCSP
/// / mTLS children handled separately above.
pub(crate) fn parse_tls_options(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TlsOptions> {
    let line = node_line(src, node);
    let min_version = prop_str(node, "min-version")
        .map(|s| parse_tls_version(&s, name, line))
        .transpose()?;
    let ciphers = node
        .children()
        .map(|doc| {
            doc.nodes()
                .iter()
                .filter(|n| n.name().value() == "cipher")
                .filter_map(|n| arg_str(n, 0))
                .collect()
        })
        .unwrap_or_default();
    Ok(TlsOptions {
        min_version,
        ciphers,
    })
}

fn parse_tls_version(
    s: &str,
    name: &str,
    line: usize,
) -> anyhow::Result<TlsVersion> {
    match s {
        "1.2" => Ok(TlsVersion::Tls12),
        "1.3" => Ok(TlsVersion::Tls13),
        other => bail!(
            "{name}:{line}: unknown TLS version '{other}'; \
             expected '1.2' or '1.3'"
        ),
    }
}
