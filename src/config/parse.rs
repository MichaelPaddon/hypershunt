use super::kdl::*;
use super::{
    BasicAuthConfig, BoundAddr, ErrorPageDef,
    GeoIpConfig, HeaderOpConfig, HealthConfig, ListenerConfig,
    LocationConfig, ProxyConfig, ProxyProtocolVersion,
    ServerConfig, SocketKind, Timeouts,
    UpstreamDtlsConfig, UpstreamTlsConfig, VHostConfig, VHostName,
};
use ::kdl::{KdlDocument, KdlNode};
use anyhow::{Context, anyhow, bail};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

mod tls;
pub(super) use tls::parse_certificate;
use tls::{parse_listener_tls, parse_tls_options};

mod auth;
use auth::parse_auth_backend;

mod handler;
use handler::parse_handler;

mod policy;
use policy::parse_policy_statements;

mod matcher;
use matcher::parse_matcher;

/// Byte offset -> 1-based line number, counting raw '\n'.  Line
/// continuations are handled automatically: newlines are counted in the
/// source text, so a `\`-continued logical line still maps to the
/// physical line the offset falls on.  The offset is clamped to a char
/// boundary first so slicing can never panic on multibyte input.
pub(super) fn line_of_offset(src: &str, offset: usize) -> usize {
    let mut off = offset.min(src.len());
    while off > 0 && !src.is_char_boundary(off) {
        off -= 1;
    }
    src[..off].bytes().filter(|&b| b == b'\n').count() + 1
}

pub(super) fn node_line(src: &str, node: &KdlNode) -> usize {
    line_of_offset(src, node.span().offset())
}

/// Levenshtein edit distance, computed with a single rolling row.
/// Used only to suggest near-miss node names in config errors, so the
/// inputs are always short identifiers.
fn edit_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0usize; b_chars.len() + 1];
    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] =
                (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_chars.len()]
}

/// Return ` -- did you mean 'X'?` when `word` is within edit distance 2
/// of some candidate, else an empty string (so it can be appended to an
/// error message unconditionally).  Picks the closest candidate; ties
/// resolve to declaration order.
pub(super) fn did_you_mean(word: &str, candidates: &[&str]) -> String {
    candidates
        .iter()
        .map(|c| (edit_distance(word, c), *c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| format!(" -- did you mean '{c}'?"))
        .unwrap_or_default()
}

/// Node names that are only ever legal at the top level of a config.
/// None of them is a valid child node name anywhere in the grammar, so
/// finding one nested inside a block is an unambiguous mistake.
pub(super) const TOP_LEVEL_ONLY: [&str; 4] =
    ["server", "listener", "vhost", "certificate"];

/// Reject a top-level-only node that appears nested inside another
/// block.  Balanced-but-misnested braces (e.g. an unclosed `server {`
/// that swallows the listeners below it) parse as perfectly valid KDL,
/// so the parser never complains -- the user instead sees a baffling
/// downstream error like "config must define at least one listener".
/// Catching the misplacement here points straight at the real cause.
pub(super) fn check_misnesting(
    src: &str,
    name: &str,
    doc: &KdlDocument,
) -> anyhow::Result<()> {
    for node in doc.nodes() {
        let Some(children) = node.children() else {
            continue;
        };
        let parent = node.name().value();
        for child in children.nodes() {
            let cn = child.name().value();
            // A `vhost` inside a `listener` is a legal reference list
            // (selecting which top-level vhosts the listener serves),
            // not a misnested definition -- so exempt that one pairing.
            if parent == "listener" && cn == "vhost" {
                continue;
            }
            if TOP_LEVEL_ONLY.contains(&cn) {
                let line = node_line(src, child);
                let parent_line = node_line(src, node);
                let loc = if name.is_empty() {
                    format!("line {line}")
                } else {
                    format!("{name}:{line}")
                };
                bail!(
                    "{loc}: '{cn}' cannot be nested inside another \
                     block (found under '{parent}' opened at line \
                     {parent_line}) -- unclosed '{{'?"
                );
            }
        }
        // Recurse so misnesting at any depth is caught.
        check_misnesting(src, name, children)?;
    }
    Ok(())
}

// Property readers.  Positional args use `arg_str`; repeated
// single-arg children use `repeated_strs`.
pub(super) fn prop_str(node: &KdlNode, key: &str) -> Option<String> {
    node.get(key).and_then(|e| e.as_string()).map(String::from)
}
pub(super) fn prop_bool(node: &KdlNode, key: &str) -> Option<bool> {
    node.get(key).and_then(|e| e.as_bool())
}
pub(super) fn prop_i64(node: &KdlNode, key: &str) -> Option<i64> {
    node.get(key).and_then(|e| e.as_integer()).map(|n| n as i64)
}

// Collect every value of a repeating single-arg child by name.
//   children:  domain "a"; domain "b"  ->  ["a", "b"]
pub(super) fn repeated_strs(node: &KdlNode, key: &str) -> Vec<String> {
    node.children()
        .map(|doc| {
            doc.nodes()
                .iter()
                .filter(|n| n.name().value() == key)
                .filter_map(|n| arg_str(n, 0))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn parse_server(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<ServerConfig> {
    let tls_defaults = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "tls-options")
        })
        .map(|n| parse_tls_options(n, src, name))
        .transpose()?
        .unwrap_or_default();
    let auth = node
        .children()
        .and_then(|doc| doc.nodes().iter().find(|n| n.name().value() == "auth"))
        .map(|n| parse_auth_backend(n, src, name))
        .transpose()?;
    let geoip = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "geoip")
        })
        .map(|n| parse_geoip(n, src, name))
        .transpose()?;
    let health = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "health")
        })
        .map(|n| {
            // `health enabled=#false` disables; `liveness-path` /
            // `readiness-path` repeating children override the default
            // path sets (empty -> defaults).
            let default = HealthConfig::default();
            let liveness = repeated_strs(n, "liveness-path");
            let readiness = repeated_strs(n, "readiness-path");
            HealthConfig {
                enabled: prop_bool(n, "enabled").unwrap_or(true),
                liveness_paths: if liveness.is_empty() {
                    default.liveness_paths
                } else {
                    liveness
                },
                readiness_paths: if readiness.is_empty() {
                    default.readiness_paths
                } else {
                    readiness
                },
            }
        })
        .unwrap_or_default();
    // Collect named policy blocks defined in the server node.
    let mut policies = HashMap::new();
    for child in node.children().map(|d| d.nodes()).unwrap_or_default() {
        let child_name = child.name().value();
        if child_name == "policy" {
            let child_line = node_line(src, child);
            let policy_name = arg_str(child, 0).ok_or_else(|| {
                anyhow!(
                    "{name}:{child_line}: 'policy' requires \
                     a name argument"
                )
            })?;
            let stmts = parse_policy_statements(child, src, name, false)?;
            if policies.insert(policy_name.clone(), stmts).is_some() {
                bail!(
                    "{name}:{child_line}: duplicate policy \
                     name '{policy_name}'"
                );
            }
        }
    }

    // Collect error-page entries from the server node.
    let mut error_pages = Vec::new();
    for child in node.children().map(|d| d.nodes()).unwrap_or_default() {
        if child.name().value() == "error-page" {
            let child_line = node_line(src, child);
            let code = child
                .entries()
                .iter()
                .find(|e| e.name().is_none())
                .and_then(|e| e.value().as_integer())
                .map(|n| n as u16)
                .ok_or_else(|| {
                    anyhow!(
                        "{name}:{child_line}: 'error-page' requires a \
                     numeric status code as first argument"
                    )
                })?;
            let path = child.get("path").and_then(|e| e.as_string());
            let html = child.get("html").and_then(|e| e.as_string());
            let def = match (path, html) {
                (Some(_), Some(_)) => bail!(
                    "{name}:{child_line}: 'error-page' accepts only one \
                     of path=\"...\" or html=\"...\""
                ),
                (Some(p), None) => ErrorPageDef::File(p.to_owned()),
                (None, Some(h)) => ErrorPageDef::Inline(h.to_owned()),
                (None, None) => bail!(
                    "{name}:{child_line}: 'error-page' requires \
                     path=\"...\" or html=\"...\" property"
                ),
            };
            error_pages.push((code, def));
        }
    }

    let access_log = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "access-log")
        })
        .map(|n| parse_access_log(n, src, name))
        .transpose()?;

    // Reload / binary-upgrade tunables.  Both default to safe values
    // when the operator hasn't set them; both reject negatives so a
    // misconfigured value fails parse rather than silently behaving
    // like 0.
    let graceful_drain_timeout =
        parse_nonneg_u32(node, "graceful-drain-timeout", 0)
            .context("server.graceful-drain-timeout")?;
    let upgrade_startup_timeout =
        parse_nonneg_u32(node, "upgrade-startup-timeout", 60)
            .context("server.upgrade-startup-timeout")?;
    let lame_duck_timeout = parse_nonneg_u32(node, "lame-duck-timeout", 0)
        .context("server.lame-duck-timeout")?;

    let cache = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "cache")
        })
        .map(|n| parse_cache_global(n, src, name))
        .transpose()?;

    Ok(ServerConfig {
        state_dir: prop_str(node, "state-dir"),
        tls_defaults,
        user: prop_str(node, "user"),
        group: prop_str(node, "group"),
        inherit_supplementary_groups: prop_bool(
            node,
            "inherit-supplementary-groups",
        )
        .unwrap_or(false),
        auth,
        geoip,
        health,
        policies,
        cache,
        error_pages,
        cert_key_mode: parse_file_mode(node, "cert-key-mode")
            .context("server.cert-key-mode")?,
        access_log,
        graceful_drain_timeout,
        upgrade_startup_timeout,
        lame_duck_timeout,
    })
}

// Helper: read a non-negative-integer property.  Returns the default
// when absent; errors when present but negative (catches the "I typed
// -1 expecting 'never'" footgun rather than silently overflowing to a
// huge u32).
fn parse_nonneg_u32(
    node: &KdlNode,
    key: &str,
    default: u32,
) -> anyhow::Result<u32> {
    match prop_i64(node, key) {
        Some(v) if v >= 0 && v <= u32::MAX as i64 => Ok(v as u32),
        Some(v) => bail!(
            "'{key}' must be a non-negative integer (got {v})"
        ),
        None => Ok(default),
    }
}

// Parse `access-log "<format>" path="..."` (single-line form).  The
// positional format is mandatory; without it we error rather than
// silently fall back to a different format than the operator asked
// for.  The path is optional for non-tracing formats (stderr if
// absent) and ignored for `tracing`.
fn parse_access_log(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::AccessLogConfig> {
    use crate::config::{AccessLogConfig, AccessLogFormatConfig};
    let line = node_line(src, node);
    let format_str = req_arg_str(node, 0).with_context(|| {
        format!(
            "{name}:{line}: access-log requires a format as its first \
             argument (tracing | json | common | combined)"
        )
    })?;
    let format = match format_str.as_str() {
        "tracing" => AccessLogFormatConfig::Tracing,
        "json" => AccessLogFormatConfig::Json,
        "common" => AccessLogFormatConfig::Common,
        "combined" => AccessLogFormatConfig::Combined,
        other => bail!(
            "{name}:{line}: unknown access-log format {other:?}; \
             expected one of: tracing, json, common, combined"
        ),
    };
    let path = prop_str(node, "path");
    Ok(AccessLogConfig { format, path })
}

// Parse an octal file-mode string such as "0640" or "0o640".
// Returns None if the property is absent.
fn parse_file_mode(node: &KdlNode, key: &str) -> anyhow::Result<Option<u32>> {
    let Some(s) = prop_str(node, key) else {
        return Ok(None);
    };
    let digits = s
        .strip_prefix("0o")
        .or_else(|| s.strip_prefix('0'))
        .unwrap_or(s.as_str());
    u32::from_str_radix(digits, 8)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("invalid octal mode: {s:?}"))
}

fn parse_geoip(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<GeoIpConfig> {
    let line = node_line(src, node);
    let db = prop_str(node, "db").ok_or_else(|| {
        anyhow!(
            "{name}:{line}: geoip requires db=\"<path-to-.mmdb>\""
        )
    })?;
    Ok(GeoIpConfig { db })
}

// Parse a `listener` node.  The listener's effective vhost set is
// resolved later by the router (implicit = all non-explicit-only
// vhosts; explicit = the `vhost` reference list, first entry default).
pub(super) fn parse_listener(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<ListenerConfig> {
    let line = node_line(src, node);
    let bind_str = req_arg_str(node, 0).with_context(|| {
        format!("{name}:{line}: listener requires a bind URL")
    })?;
    let bind = BoundAddr::parse(&bind_str)
        .with_context(|| format!("{name}:{line}: invalid listener bind"))?;
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    // Encryption layer.  A single `tls "<kind>"` node serves every
    // socket family; the family decides its meaning (cross-checked in
    // validate()):
    //   tls on byte-stream     -> HTTPS
    //   tls on udp://          -> HTTP/3 (QUIC's encryption IS TLS 1.3)
    //   tls + proxy on udp://  -> DTLS-terminating dgram proxy (reserved)
    let tls = parse_listener_tls(children.iter(), src, name)?;
    // Whether `tls` is legal on this socket family is left to
    // validate(): byte-stream -> HTTPS, udp:// -> HTTP/3, every other
    // datagram kind -> rejected.
    // Optional repeated `alpn "h2"; alpn "http/1.1"` children override
    // the listener's default ALPN list.  An empty list (no children)
    // means "use defaults"; an `alpn` child with no positional value
    // is a config error rather than a silent skip.
    for c in children.iter() {
        if c.name().value() == "alpn"
            && c.entries().iter().all(|e| e.name().is_some())
        {
            let ln = node_line(src, c);
            bail!(
                "{name}:{ln}: 'alpn' requires a protocol identifier \
                 (e.g. `alpn \"h2\"`)"
            );
        }
    }
    let alpn_values = repeated_strs(node, "alpn");
    let alpn = if alpn_values.is_empty() {
        None
    } else {
        Some(alpn_values)
    };
    // Optional `quic-transport ...` block.  All knobs are properties
    // on the node; absent knobs fall back to quinn defaults.  Only
    // meaningful for udp: listeners but parsed unconditionally so
    // misplaced config produces a clear error rather than being
    // silently ignored.
    let quic_transport: Option<crate::config::QuicTransport> = children
        .iter()
        .find(|n| n.name().value() == "quic-transport")
        .map(|n| -> anyhow::Result<crate::config::QuicTransport> {
            let line = node_line(src, n);
            if bind.kind != SocketKind::UdpDgram {
                bail!(
                    "{name}:{line}: 'quic-transport' is only valid on \
                     udp:// listeners"
                );
            }
            Ok(crate::config::QuicTransport {
                max_concurrent_bidi_streams: prop_i64(
                    n, "max-concurrent-bidi-streams",
                )
                .map(|v| v as u64),
                max_idle_timeout_secs: prop_i64(n, "max-idle-timeout")
                    .map(|v| v as u64),
                keep_alive_interval_secs: prop_i64(n, "keep-alive-interval")
                    .map(|v| v as u64),
                zero_rtt_enabled: prop_bool(n, "zero-rtt").unwrap_or(false),
                retry_tokens: prop_bool(n, "retry-tokens").unwrap_or(true),
                retry_token_lifetime_secs: prop_i64(
                    n, "retry-token-lifetime",
                )
                .map(|v| v as u64),
            })
        })
        .transpose()?;
    // A 'proxy' child activates proxy mode.  Stream listeners forward
    // by connection, message listeners forward by datagram; the
    // upstream URL scheme must match the listener's family (validated
    // in Config::validate).
    let proxy_node = children.iter().find(|n| n.name().value() == "proxy");
    if let Some(proxy) = proxy_node {
        let proxy_line = node_line(src, proxy);
        // HTTP-only options are invalid in L4-proxy mode: an L4 proxy
        // forwards bytes/datagrams and never routes by virtual host.
        if children.iter().any(|n| n.name().value() == "vhost") {
            bail!(
                "{name}:{proxy_line}: 'vhost' is only valid in HTTP \
                 listeners; L4 proxy listeners do not route by virtual \
                 host"
            );
        }
        if node.get("reject-unknown-host").is_some() {
            bail!(
                "{name}:{proxy_line}: 'reject-unknown-host' is only \
                 valid in HTTP listeners"
            );
        }
        if node.get("health").is_some() {
            bail!(
                "{name}:{proxy_line}: 'health' is only valid in HTTP \
                 listeners"
            );
        }
        if children.iter().any(|n| n.name().value() == "timeouts") {
            bail!(
                "{name}:{proxy_line}: 'timeouts' is only valid in HTTP \
                 listeners"
            );
        }
        let upstream_str = req_arg_str(proxy, 0)
            .with_context(|| format!("{name}:{proxy_line}"))?;
        let upstream = BoundAddr::parse(&upstream_str).with_context(
            || format!("{name}:{proxy_line}: invalid proxy upstream"),
        )?;
        let proxy_children =
            proxy.children().map(|d| d.nodes()).unwrap_or_default();
        let upstream_tls = proxy_children
            .iter()
            .find(|n| n.name().value() == "tls")
            .map(|tls_node| UpstreamTlsConfig {
                skip_verify: prop_bool(tls_node, "skip-verify")
                    .unwrap_or(false),
            });
        // `dtls` upstream block: reserved syntactically.  Carry an
        // empty UpstreamDtlsConfig so validate() can bail with "not
        // yet implemented" downstream.
        let upstream_dtls = proxy_children
            .iter()
            .find(|n| n.name().value() == "dtls")
            .map(|q_node| UpstreamDtlsConfig {
                skip_verify: prop_bool(q_node, "skip-verify")
                    .unwrap_or(false),
            });
        let proxy_protocol = prop_str(proxy, "proxy-protocol")
            .map(|v| parse_proxy_protocol(&v, name, proxy_line))
            .transpose()?;
        let flow_idle_timeout_secs =
            prop_i64(proxy, "flow-idle-timeout").map(|v| v as u64);
        let policy = children
            .iter()
            .find(|n| n.name().value() == "policy")
            .map(|n| parse_policy_statements(n, src, name, true))
            .transpose()?;
        let proxy_cfg = Some(ProxyConfig {
            upstream,
            upstream_tls,
            upstream_dtls,
            proxy_protocol,
            policy,
            flow_idle_timeout_secs,
        });
        let accept_proxy_protocol = prop_str(node, "accept-proxy-protocol")
            .map(|v| parse_proxy_protocol(&v, name, line))
            .transpose()?;
        let trusted_proxies = parse_trusted_proxies(node, src, name)?;
        if !trusted_proxies.is_empty() && accept_proxy_protocol.is_none() {
            bail!(
                "{name}:{line}: 'trusted-proxies' requires \
                 'accept-proxy-protocol' on the same listener"
            );
        }
        let max_connections =
            prop_i64(node, "max-connections").map(|n| n as u32);
        return Ok(ListenerConfig {
            bind,
            tls,
            proxy: proxy_cfg,
            accept_proxy_protocol,
            trusted_proxies,
            vhosts: Vec::new(),
            reject_unknown_host: false,
            health: None,
            timeouts: Timeouts::default(),
            max_connections,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: alpn.clone(),
            quic_transport: quic_transport.clone(),
            line,
        });
    }

    // HTTP mode.
    if let Some(bad) = children.iter().find(|n| n.name().value() == "policy") {
        let line = node_line(src, bad);
        bail!(
            "{name}:{line}: 'policy' at the listener level is only valid \
             for stream listeners; put 'policy' inside a 'location' block"
        );
    }
    // Vhost reference list.  Each `vhost` child contributes its
    // positional args (e.g. `vhost "lan" "admin"`); multiple children
    // concatenate, preserving order.  A `vhost` child is a *reference*,
    // not a definition: it carries no block and at least one name.
    let mut vhosts: Vec<String> = Vec::new();
    for c in children.iter().filter(|n| n.name().value() == "vhost") {
        let cl = node_line(src, c);
        if c.children().is_some() {
            bail!(
                "{name}:{cl}: a 'vhost' inside a listener is a reference \
                 to a top-level vhost and cannot have a block; define \
                 the vhost at top level and list its name here"
            );
        }
        let refs = arg_strs(c);
        if refs.is_empty() {
            bail!(
                "{name}:{cl}: 'vhost' requires at least one vhost name \
                 (e.g. `vhost \"example.com\"`)"
            );
        }
        vhosts.extend(refs);
    }
    let reject_unknown_host =
        prop_bool(node, "reject-unknown-host").unwrap_or(false);
    let timeouts = children
        .iter()
        .find(|n| n.name().value() == "timeouts")
        .map(parse_timeouts)
        .unwrap_or_default();
    let accept_proxy_protocol = prop_str(node, "accept-proxy-protocol")
        .map(|v| parse_proxy_protocol(&v, name, line))
        .transpose()?;
    let trusted_proxies = parse_trusted_proxies(node, src, name)?;
    if !trusted_proxies.is_empty() && accept_proxy_protocol.is_none() {
        bail!(
            "{name}:{line}: 'trusted-proxies' requires \
             'accept-proxy-protocol' on the same listener"
        );
    }
    let max_connections =
        prop_i64(node, "max-connections").map(|n| n as u32);
    let max_request_body =
        prop_i64(node, "max-request-body").map(|n| n as u64);
    Ok(ListenerConfig {
        bind,
        tls,
        proxy: None,
        accept_proxy_protocol,
        trusted_proxies,
        vhosts,
        reject_unknown_host,
        health: prop_bool(node, "health"),
        timeouts,
        max_connections,
        max_request_body,
        auto_alt_svc: None,
        alpn: alpn.clone(),
        quic_transport: quic_transport.clone(),
        line,
    })
}

// Parse the listener's repeating `trusted-proxies "<cidr>"` children
// into a Vec<IpNet>.  Accepts bare IP addresses (treated as /32 or
// /128) or CIDR ranges.  An empty list means "no allowlist enforced";
// only malformed entries are rejected.
fn parse_trusted_proxies(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<Vec<IpNet>> {
    let mut nets = Vec::new();
    let Some(children) = node.children() else {
        return Ok(nets);
    };
    for n in children.nodes() {
        if n.name().value() != "trusted-proxies" {
            continue;
        }
        let line = node_line(src, n);
        let s = req_arg_str(n, 0).with_context(|| {
            format!(
                "{name}:{line}: trusted-proxies requires a single IP \
                 address or CIDR argument (repeat the node for more \
                 entries)"
            )
        })?;
        let net = s
            .parse::<IpNet>()
            .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| {
                anyhow!(
                    "{name}:{line}: invalid IP address or CIDR '{s}' \
                     in 'trusted-proxies'"
                )
            })?;
        nets.push(net);
    }
    Ok(nets)
}

pub(super) fn parse_proxy_protocol(
    v: &str,
    name: &str,
    line: usize,
) -> anyhow::Result<ProxyProtocolVersion> {
    match v {
        "v1" => Ok(ProxyProtocolVersion::V1),
        "v2" => Ok(ProxyProtocolVersion::V2),
        other => bail!(
            "{name}:{line}: unknown proxy-protocol '{other}'; \
             expected 'v1' or 'v2'"
        ),
    }
}

fn parse_timeouts(node: &KdlNode) -> Timeouts {
    Timeouts {
        request_header_secs: prop_i64(node, "request-header")
            .map(|n| n as u64),
        handler_secs: prop_i64(node, "handler").map(|n| n as u64),
        keepalive_secs: prop_i64(node, "keepalive").map(|n| n as u64),
    }
}

pub(super) fn parse_vhost(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<VHostConfig> {
    let vhost_name = parse_vhost_name(node)?;
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut aliases = Vec::new();
    let mut locations = Vec::new();
    for child in children {
        let child_line = node_line(src, child);
        match child.name().value() {
            "alias" => aliases.push(parse_vhost_name(child)?),
            "location" => locations.push(parse_location(child, src, name)?),
            "alpn" => {
                // Single-arg repeating child (rule 4); collected
                // below via repeated_strs.  An `alpn` child with no
                // positional value is a config error rather than a
                // silent skip.
                if child.entries().iter().all(|e| e.name().is_some()) {
                    bail!(
                        "{name}:{child_line}: 'alpn' requires at \
                         least one protocol identifier (e.g. \
                         `alpn \"h2\"`)"
                    );
                }
            }
            other => bail!(
                "{name}:{child_line}: unknown node '{other}' \
                 in vhost '{}'{}",
                vhost_name.value,
                did_you_mean(other, &["alias", "location", "alpn"])
            ),
        }
    }
    let alpn_values = repeated_strs(node, "alpn");
    let alpn = if alpn_values.is_empty() {
        None
    } else {
        Some(alpn_values)
    };
    // Optional reference handle and implicit-set opt-out.
    let ref_name = prop_str(node, "name");
    let explicit_only = prop_bool(node, "explicit-only").unwrap_or(false);
    Ok(VHostConfig {
        name: vhost_name,
        aliases,
        locations,
        ref_name,
        explicit_only,
        alpn,
        line: node_line(src, node),
    })
}

fn parse_vhost_name(node: &KdlNode) -> anyhow::Result<VHostName> {
    let value = req_arg_str(node, 0)?;
    let regex = node.get("regex").and_then(|e| e.as_bool()).unwrap_or(false);
    Ok(VHostName { value, regex })
}

fn parse_location(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<LocationConfig> {
    let line = node_line(src, node);
    let path = req_arg_str(node, 0)?;
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    // The first recognised handler node wins.
    let handler_node = children
        .iter()
        .find(|n| {
            matches!(
                n.name().value(),
                "static"
                    | "proxy"
                    | "redirect"
                    | "respond"
                    | "fastcgi"
                    | "scgi"
                    | "cgi"
                    | "status"
                    | "auth-request"
            )
        })
        .ok_or_else(|| {
            anyhow!("{name}:{line}: location '{path}' has no handler node")
        })?;
    let handler = parse_handler(handler_node, src, name, &path)?;
    let policy = children
        .iter()
        .find(|n| n.name().value() == "policy")
        .map(|n| parse_policy_statements(n, src, name, false))
        .transpose()?;
    let auth = children
        .iter()
        .find(|n| n.name().value() == "basic-auth")
        .map(|n| BasicAuthConfig {
            realm: prop_str(n, "realm")
                .unwrap_or_else(|| "Restricted".to_owned()),
        });
    let request_headers = children
        .iter()
        .find(|n| n.name().value() == "request-headers")
        .map(|n| parse_header_ops(n, src, name))
        .transpose()?
        .unwrap_or_default();
    let response_headers = children
        .iter()
        .find(|n| n.name().value() == "response-headers")
        .map(|n| parse_header_ops(n, src, name))
        .transpose()?
        .unwrap_or_default();
    let mut rate_limits: Vec<crate::config::RateLimitConfig> = Vec::new();
    for (idx, n) in children
        .iter()
        .filter(|n| n.name().value() == "rate-limit")
        .enumerate()
    {
        rate_limits.push(parse_rate_limit(
            n,
            src,
            name,
            &path,
            idx,
        )?);
    }
    let max_request_body =
        prop_i64(node, "max-request-body").map(|n| n as u64);
    let matcher = children
        .iter()
        .find(|n| n.name().value() == "match")
        .map(|n| parse_matcher(n, src, name))
        .transpose()?;
    let rewrite = children
        .iter()
        .find(|n| n.name().value() == "rewrite")
        .map(|n| parse_rewrite(n, src, name))
        .transpose()?;
    let cache = children
        .iter()
        .find(|n| n.name().value() == "cache")
        .map(|n| parse_cache(n, src, name))
        .transpose()?;
    Ok(LocationConfig {
        path,
        handler,
        policy,
        auth,
        request_headers,
        response_headers,
        rate_limits,
        max_request_body,
        matcher,
        rewrite,
        cache,
        line,
    })
}

/// Default freshness cap when a location's `cache` block omits
/// `ttl`.  Conservative: only one minute of trust unless the
/// operator opts into longer.
const CACHE_DEFAULT_TTL_SECS: u64 = 60;
/// Default per-object body cap (1 MiB) when `max-object-size` is
/// omitted.  Keeps a single large response from dominating the store.
const CACHE_DEFAULT_MAX_OBJECT: u64 = 1024 * 1024;
/// Default server-wide store cap (256 MiB) when the `server` `cache`
/// block omits `max-size`.
const CACHE_DEFAULT_MAX_SIZE: u64 = 256 * 1024 * 1024;

/// Parse the server-wide `cache { max-size=N }` block.  Only sizes
/// the shared store; enabling caching is a per-location decision.
fn parse_cache_global(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::CacheGlobalConfig> {
    let line = node_line(src, node);
    let max_size = match prop_i64(node, "max-size") {
        Some(v) if v > 0 => v as u64,
        Some(v) => bail!(
            "{name}:{line}: cache `max-size` must be > 0 (got {v})"
        ),
        None => CACHE_DEFAULT_MAX_SIZE,
    };
    Ok(crate::config::CacheGlobalConfig { max_size })
}

/// Parse a per-location `cache { ttl=N max-object-size=N method "GET"
/// key="..." honor-client-cache-control=#bool }` block.  Presence of
/// the block opts the location into caching.
fn parse_cache(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::CacheConfig> {
    let line = node_line(src, node);
    let ttl_secs = match prop_i64(node, "ttl") {
        Some(v) if v >= 0 => v as u64,
        Some(v) => bail!(
            "{name}:{line}: cache `ttl` must be >= 0 (got {v})"
        ),
        None => CACHE_DEFAULT_TTL_SECS,
    };
    let max_object_size = match prop_i64(node, "max-object-size") {
        Some(v) if v > 0 => v as u64,
        Some(v) => bail!(
            "{name}:{line}: cache `max-object-size` must be > 0 \
             (got {v})"
        ),
        None => CACHE_DEFAULT_MAX_OBJECT,
    };
    // Cacheable methods come from repeating `method "GET"` children;
    // default to GET only.  Upper-cased so matching is case-stable.
    let mut methods: Vec<String> = repeated_strs(node, "method")
        .into_iter()
        .map(|m| m.to_ascii_uppercase())
        .collect();
    if methods.is_empty() {
        methods.push("GET".to_owned());
    }
    for m in &methods {
        if m != "GET" && m != "HEAD" {
            bail!(
                "{name}:{line}: cache `method` {m:?} unsupported; \
                 only GET and HEAD may be cached"
            );
        }
    }
    let key = prop_str(node, "key");
    let honor_client_cache_control =
        prop_bool(node, "honor-client-cache-control").unwrap_or(false);
    Ok(crate::config::CacheConfig {
        ttl_secs,
        max_object_size,
        methods,
        key,
        honor_client_cache_control,
    })
}

/// Parse a `rewrite from="<regex>" to="<template>"` directive on a
/// location.  Both properties are required.  The regex is compiled at
/// parse time so the operator sees malformed patterns immediately.
/// The replacement template is not validated against the capture-group
/// set here; an undefined capture quietly produces an empty substring
/// at request time, matching `regex::Regex::replace`'s behaviour.
fn parse_rewrite(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::RewriteConfig> {
    let line = node_line(src, node);
    let from = prop_str(node, "from").ok_or_else(|| {
        anyhow!("{name}:{line}: rewrite requires from=\"<regex>\"")
    })?;
    let to = prop_str(node, "to").ok_or_else(|| {
        anyhow!("{name}:{line}: rewrite requires to=\"<template>\"")
    })?;
    regex::Regex::new(&from).map_err(|e| {
        anyhow!("{name}:{line}: rewrite invalid `from` regex: {e}")
    })?;
    Ok(crate::config::RewriteConfig { from, to })
}

/// Parse one `rate-limit rate=N per="second" burst=N name="..." key=...`
/// block.  All scalars are properties on the rate-limit node; `key`
/// remains a child node because it has an internal structure
/// (`key "header" "X-Foo"`) that doesn't compress into a property.
fn parse_rate_limit(
    node: &KdlNode,
    src: &str,
    name: &str,
    loc_path: &str,
    idx: usize,
) -> anyhow::Result<crate::config::RateLimitConfig> {
    let line = node_line(src, node);
    let rate_raw = prop_i64(node, "rate").ok_or_else(|| {
        anyhow!("{name}:{line}: rate-limit requires rate=<integer>")
    })?;
    if rate_raw <= 0 {
        bail!(
            "{name}:{line}: rate-limit `rate` must be > 0 (got \
             {rate_raw})"
        );
    }
    let per_secs = match prop_str(node, "per")
        .as_deref()
        .unwrap_or("second")
    {
        "second" => 1.0,
        "minute" => 60.0,
        "hour" => 3600.0,
        other => bail!(
            "{name}:{line}: rate-limit unknown per={other:?}; \
             expected second, minute, or hour"
        ),
    };
    let rate_per_sec = rate_raw as f64 / per_secs;
    let burst = prop_i64(node, "burst")
        .map(|n| {
            if n <= 0 {
                Err(anyhow!(
                    "{name}:{line}: rate-limit `burst` must be > 0 \
                     (got {n})"
                ))
            } else {
                Ok(n as f64)
            }
        })
        .transpose()?
        .unwrap_or(rate_raw as f64);
    let key_node = node.children().and_then(|d| {
        d.nodes().iter().find(|n| n.name().value() == "key")
    });
    let key_node = key_node.ok_or_else(|| {
        anyhow!(
            "{name}:{line}: rate-limit requires a `key \"client-ip\"`, \
             `key \"user\"`, or `key \"header\" \"<Name>\"` child"
        )
    })?;
    let key = parse_rate_limit_key(key_node, src, name)?;
    let rule_name = prop_str(node, "name").unwrap_or_else(
        || format!("{}-rl-{}", loc_path.trim_matches('/'), idx),
    );
    Ok(crate::config::RateLimitConfig {
        name: rule_name,
        rate_per_sec,
        burst,
        key,
    })
}

fn parse_rate_limit_key(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::RateLimitKeyConfig> {
    let line = node_line(src, node);
    let kind = arg_str(node, 0).ok_or_else(|| {
        anyhow!(
            "{name}:{line}: rate-limit `key` requires a form \
             (client-ip | user | header \"<Name>\")"
        )
    })?;
    match kind.as_str() {
        "client-ip" => Ok(crate::config::RateLimitKeyConfig::ClientIp),
        "user" => Ok(crate::config::RateLimitKeyConfig::User),
        "header" => {
            let header = arg_str(node, 1).ok_or_else(|| {
                anyhow!(
                    "{name}:{line}: rate-limit `key \"header\"` \
                     requires a header name (e.g. `key \"header\" \
                     \"X-API-Key\"`)"
                )
            })?;
            // Validate as a real header name; reject early so the
            // runtime path can't hit a Header parse error.
            hyper::header::HeaderName::from_bytes(header.as_bytes())
                .map_err(|e| {
                    anyhow!(
                        "{name}:{line}: rate-limit invalid header \
                         name {header:?}: {e}"
                    )
                })?;
            Ok(crate::config::RateLimitKeyConfig::Header(
                header.to_ascii_lowercase(),
            ))
        }
        other => bail!(
            "{name}:{line}: rate-limit unknown key form {other:?}; \
             expected client-ip, user, or header"
        ),
    }
}


// Parse a `request-headers { }` or `response-headers { }` block.
//
//   request-headers {
//       set "X-Client-IP" "{client_ip}"
//       add "Vary"        "accept"
//       remove "Authorization"
//   }
fn parse_header_ops(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<Vec<HeaderOpConfig>> {
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    let parse_two_arg = |child: &KdlNode,
                         op: &str,
                         child_line: usize|
     -> anyhow::Result<(String, String)> {
        let hname = req_arg_str(child, 0)
            .with_context(|| format!("{name}:{child_line}"))?;
        let value = req_arg_str(child, 1).with_context(|| {
            anyhow!(
                "{name}:{child_line}: '{op}' requires a \
                 header name and a value"
            )
        })?;
        Ok((hname, value))
    };
    let mut ops = Vec::new();
    for child in children {
        let child_line = node_line(src, child);
        match child.name().value() {
            "set" => {
                let (hname, value) = parse_two_arg(child, "set", child_line)?;
                ops.push(HeaderOpConfig::Set { name: hname, value });
            }
            "add" => {
                let (hname, value) = parse_two_arg(child, "add", child_line)?;
                ops.push(HeaderOpConfig::Add { name: hname, value });
            }
            "remove" => {
                let hname = req_arg_str(child, 0)
                    .with_context(|| format!("{name}:{child_line}"))?;
                ops.push(HeaderOpConfig::Remove { name: hname });
            }
            other => bail!(
                "{name}:{child_line}: unknown header operation \
                 '{other}'; expected 'set', 'add', or 'remove'"
            ),
        }
    }
    Ok(ops)
}

