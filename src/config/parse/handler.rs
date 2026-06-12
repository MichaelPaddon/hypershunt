// Per-location handler parsing: dispatches `static`, `proxy`,
// `redirect`, `fastcgi`, `scgi`, `cgi`, `status`, and `auth-request`
// into typed `HandlerConfig` variants.

use super::super::kdl::*;
use super::super::{HandlerConfig, RespondBody, UpstreamTlsConfig};
use super::{
    node_line, parse_proxy_protocol, prop_bool, prop_i64, prop_str,
    repeated_strs,
};
use ::kdl::KdlNode;
use anyhow::{Context, anyhow, bail};
use hyper::header::HeaderValue;

pub(super) fn parse_handler(
    node: &KdlNode,
    src: &str,
    name: &str,
    location_path: &str,
) -> anyhow::Result<HandlerConfig> {
    let line = node_line(src, node);
    match node.name().value() {
        "static" => parse_static(node, src, name),
        "proxy" => parse_proxy(node, src, name),
        "redirect" => parse_redirect(node, src, name),
        "respond" => parse_respond(node, src, name),
        "fastcgi" => {
            let (socket, root, index) =
                parse_socket_handler(node, src, name, "fastcgi")?;
            Ok(HandlerConfig::FastCgi { socket, root, index })
        }
        "scgi" => {
            let (socket, root, index) =
                parse_socket_handler(node, src, name, "scgi")?;
            Ok(HandlerConfig::Scgi { socket, root, index })
        }
        "cgi" => {
            let root = prop_str(node, "root").ok_or_else(|| {
                anyhow!(
                    "{name}:{line}: cgi handler requires \
                     root=\"<directory>\""
                )
            })?;
            Ok(HandlerConfig::Cgi { root })
        }
        "status" => Ok(HandlerConfig::Status),
        "auth-request" => Ok(HandlerConfig::AuthRequest),
        other => bail!(
            "{name}:{line}: unknown handler '{other}' \
             in location '{location_path}'"
        ),
    }
}

// `fastcgi` and `scgi` share the same socket/root/index shape;
// `index` is optional and falls back to the gateway's own default
// when absent.
fn parse_socket_handler(
    node: &KdlNode,
    src: &str,
    name: &str,
    variant: &str,
) -> anyhow::Result<(String, String, Option<String>)> {
    let line = node_line(src, node);
    let socket = prop_str(node, "socket").ok_or_else(|| {
        anyhow!(
            "{name}:{line}: {variant} handler requires \
             socket=\"<unix-stream:/... | host:port>\""
        )
    })?;
    // The runtime connector recognises the short `unix:` prefix;
    // accept the listener bind-URL spelling `unix-stream:` too and
    // normalise it here so the docs can use one scheme everywhere.
    let socket = match socket.strip_prefix("unix-stream:") {
        Some(path) => format!("unix:{path}"),
        None => socket,
    };
    let root = prop_str(node, "root").ok_or_else(|| {
        anyhow!("{name}:{line}: {variant} handler requires root=\"...\"")
    })?;
    Ok((socket, root, prop_str(node, "index")))
}

fn parse_static(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<HandlerConfig> {
    let line = node_line(src, node);
    // Either `root` (filesystem mode) or `userdir` (per-user mode) is
    // required.  Both at once is a config error.
    let root = prop_str(node, "root");
    let userdir = prop_str(node, "userdir");
    match (&root, &userdir) {
        (None, None) => bail!(
            "{name}:{line}: static handler requires either \
             root=\"<dir>\" or userdir=\"<subdir>\" (per-user mode)"
        ),
        (Some(_), Some(_)) => bail!(
            "{name}:{line}: static handler cannot set both root= and \
             userdir= on the same block"
        ),
        _ => {}
    }
    let strip_prefix =
        prop_bool(node, "strip-prefix").unwrap_or(false);
    let directory_listing =
        prop_bool(node, "directory-listing").unwrap_or(false);
    let userdir_allowlist = repeated_strs(node, "userdir-allowlist");
    let userdir_min_uid =
        prop_i64(node, "userdir-min-uid").map(|n| n as u32).unwrap_or(1000);
    if userdir.is_none()
        && (!userdir_allowlist.is_empty()
            || prop_i64(node, "userdir-min-uid").is_some())
    {
        bail!(
            "{name}:{line}: 'userdir-allowlist' / 'userdir-min-uid' \
             are only valid when 'userdir' is also set"
        );
    }
    let index_files = repeated_strs(node, "index-file");
    let index_files = if index_files.is_empty() {
        vec!["index.html".into(), "index.htm".into()]
    } else {
        index_files
    };
    let try_files = repeated_strs(node, "try-files");
    let fallback_redirect = prop_str(node, "fallback-redirect");
    Ok(HandlerConfig::Static {
        root,
        index_files,
        strip_prefix,
        try_files,
        directory_listing,
        userdir,
        userdir_allowlist,
        userdir_min_uid,
        fallback_redirect,
    })
}

fn parse_proxy(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<HandlerConfig> {
    let line = node_line(src, node);
    // Upstream(s) come from repeated `upstream "url" [weight=N]` child
    // nodes -- never as a positional or property on `proxy` itself.
    let mut upstreams: Vec<crate::config::UpstreamConfig> = Vec::new();
    if let Some(doc) = node.children() {
        for child in doc.nodes() {
            if child.name().value() != "upstream" {
                continue;
            }
            let url = req_arg_str(child, 0).with_context(|| {
                format!(
                    "{name}:{}: upstream requires a URL",
                    node_line(src, child)
                )
            })?;
            let weight = child
                .get("weight")
                .and_then(|e| e.as_integer())
                .map(|n| n as u32)
                .unwrap_or(1);
            upstreams.push(crate::config::UpstreamConfig { url, weight });
        }
    }
    if upstreams.is_empty() {
        bail!(
            "{name}:{line}: proxy handler requires at least one \
             `upstream \"<url>\"` child"
        );
    }
    let strip_prefix = prop_bool(node, "strip-prefix").unwrap_or(false);
    let proxy_protocol = prop_str(node, "proxy-protocol")
        .map(|v| parse_proxy_protocol(&v, name, line))
        .transpose()?;
    // `scheme "h3"` requires every upstream to be https://.
    let scheme = match prop_str(node, "scheme").as_deref() {
        None | Some("") | Some("auto") => {
            crate::config::ProxyUpstreamScheme::Auto
        }
        Some("h3") | Some("http3") => {
            for u in &upstreams {
                if !u.url.starts_with("https://") {
                    bail!(
                        "{name}:{line}: proxy scheme=\"h3\" requires \
                         an https:// upstream (got {:?})",
                        u.url
                    );
                }
            }
            crate::config::ProxyUpstreamScheme::H3
        }
        Some("h2c") => {
            for u in &upstreams {
                if !u.url.starts_with("http://") {
                    bail!(
                        "{name}:{line}: proxy scheme=\"h2c\" requires \
                         an http:// upstream (got {:?})",
                        u.url
                    );
                }
            }
            crate::config::ProxyUpstreamScheme::H2c
        }
        Some(other) => bail!(
            "{name}:{line}: unknown proxy scheme {other:?}; expected \
             \"auto\", \"h2c\", \"h3\", or \"http3\""
        ),
    };
    let pool_idle_timeout_secs =
        prop_i64(node, "pool-idle-timeout").map(|n| n as u64);
    let pool_max_idle = prop_i64(node, "pool-max-idle").map(|n| n as u32);
    let connect_timeout_secs =
        prop_i64(node, "connect-timeout").map(|n| n as u64);
    // `tls skip-verify=#true` applies to every https upstream in the
    // pool.  Presence with no skip-verify still implies "use TLS but
    // verify certs" (the default would do that anyway, so the node is
    // essentially a marker).
    let upstream_tls: Option<UpstreamTlsConfig> = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "tls")
        })
        .map(|tls_node| -> anyhow::Result<UpstreamTlsConfig> {
            let skip_verify =
                prop_bool(tls_node, "skip-verify").unwrap_or(false);
            if skip_verify {
                for u in &upstreams {
                    if !u.url.starts_with("https://") {
                        bail!(
                            "{name}:{line}: proxy 'tls skip-verify' is \
                             only meaningful for https:// upstreams \
                             (got {:?})",
                            u.url
                        );
                    }
                }
            }
            Ok(UpstreamTlsConfig { skip_verify })
        })
        .transpose()?;
    // `lb-policy "<kind>"` -- positional kind, optional `header=` for
    // header-hash only.
    let lb_node = node.children().and_then(|d| {
        d.nodes().iter().find(|n| n.name().value() == "lb-policy")
    });
    let (lb_policy, lb_hash_header) = match lb_node {
        None => (
            crate::config::LbPolicy::RoundRobin,
            None::<String>,
        ),
        Some(n) => {
            let policy_str = arg_str(n, 0).unwrap_or_default();
            let policy = match policy_str.as_str() {
                "" | "round-robin" => {
                    crate::config::LbPolicy::RoundRobin
                }
                "least-conn" => crate::config::LbPolicy::LeastConn,
                "random" => crate::config::LbPolicy::Random,
                "ip-hash" => crate::config::LbPolicy::IpHash,
                "header-hash" => crate::config::LbPolicy::HeaderHash,
                other => bail!(
                    "{name}:{}: unknown lb-policy {other:?}; expected \
                     \"round-robin\", \"least-conn\", \"random\", \
                     \"ip-hash\", or \"header-hash\"",
                    node_line(src, n)
                ),
            };
            let header = prop_str(n, "header");
            if policy == crate::config::LbPolicy::HeaderHash
                && header.as_deref().map(str::is_empty).unwrap_or(true)
            {
                bail!(
                    "{name}:{}: lb-policy \"header-hash\" requires \
                     header=\"<name>\"",
                    node_line(src, n)
                );
            }
            if policy != crate::config::LbPolicy::HeaderHash
                && header.is_some()
            {
                bail!(
                    "{name}:{}: header=\"...\" is only valid with \
                     lb-policy \"header-hash\"",
                    node_line(src, n)
                );
            }
            (policy, header)
        }
    };
    let active_health = parse_active_health(node, src, name)?;
    let passive_health = parse_passive_health(node);
    let retry = parse_retry(node, src, name)?;
    Ok(HandlerConfig::Proxy {
        upstreams,
        lb_policy,
        lb_hash_header,
        active_health,
        passive_health,
        retry,
        strip_prefix,
        proxy_protocol,
        scheme,
        pool_idle_timeout_secs,
        pool_max_idle,
        upstream_tls,
        connect_timeout_secs,
    })
}

fn parse_active_health(
    node: &KdlNode,
    _src: &str,
    _name: &str,
) -> anyhow::Result<Option<crate::config::ActiveHealthConfig>> {
    let Some(hc) = node
        .children()
        .and_then(|d| {
            d.nodes().iter().find(|n| n.name().value() == "active-health")
        })
    else {
        return Ok(None);
    };
    let path = prop_str(hc, "path").unwrap_or_else(|| "/".to_string());
    let interval_secs =
        prop_i64(hc, "interval").map(|n| n as u64).unwrap_or(10);
    let timeout_secs =
        prop_i64(hc, "timeout").map(|n| n as u64).unwrap_or(2);
    let expect_status =
        prop_i64(hc, "expect-status").map(|n| n as u16).unwrap_or(200);
    let unhealthy_after =
        prop_i64(hc, "unhealthy-after").map(|n| n as u32).unwrap_or(2);
    let healthy_after =
        prop_i64(hc, "healthy-after").map(|n| n as u32).unwrap_or(1);
    Ok(Some(crate::config::ActiveHealthConfig {
        path,
        interval_secs,
        timeout_secs,
        expect_status,
        unhealthy_after,
        healthy_after,
    }))
}

fn parse_passive_health(node: &KdlNode) -> crate::config::PassiveHealthConfig {
    let Some(ph) = node
        .children()
        .and_then(|d| {
            d.nodes().iter().find(|n| n.name().value() == "passive-health")
        })
    else {
        return crate::config::PassiveHealthConfig::default();
    };
    crate::config::PassiveHealthConfig {
        eject_after: prop_i64(ph, "eject-after")
            .map(|n| n as u32)
            .unwrap_or(u32::MAX),
        eject_for_secs: prop_i64(ph, "eject-for")
            .map(|n| n as u64)
            .unwrap_or(30),
    }
}

fn parse_retry(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::RetryConfig> {
    let Some(r) = node
        .children()
        .and_then(|d| {
            d.nodes().iter().find(|n| n.name().value() == "retry")
        })
    else {
        return Ok(crate::config::RetryConfig::default());
    };
    let max = prop_i64(r, "max").map(|n| n as u32).unwrap_or(0);
    // `on-status` is a repeating single-arg child: each child carries
    // one HTTP status code that should trigger a retry.  When max>0
    // the list must be non-empty so it is explicit which codes
    // qualify.
    let on_status: Vec<u16> = r
        .children()
        .map(|d| {
            d.nodes()
                .iter()
                .filter(|n| n.name().value() == "on-status")
                .filter_map(|n| {
                    n.entries().first().and_then(|e| {
                        e.value().as_integer().map(|v| v as u16)
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if max > 0 && on_status.is_empty() {
        bail!(
            "{name}:{}: retry max={max} requires `on-status N` \
             children listing the status codes that trigger a retry",
            node_line(src, r)
        );
    }
    Ok(crate::config::RetryConfig { max, on_status })
}

fn parse_redirect(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<HandlerConfig> {
    let line = node_line(src, node);
    let to = prop_str(node, "to").ok_or_else(|| {
        anyhow!("{name}:{line}: redirect handler requires to=\"<url>\"")
    })?;
    let code = prop_i64(node, "code").map(|n| n as u16).unwrap_or(301);
    Ok(HandlerConfig::Redirect { to, code })
}

fn parse_respond(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<HandlerConfig> {
    let line = node_line(src, node);
    // status defaults to 200 (a bare `respond` is a valid 200 endpoint).
    let status = match prop_i64(node, "status") {
        Some(n) if (100..=599).contains(&n) => n as u16,
        Some(n) => bail!(
            "{name}:{line}: respond status must be 100-599, got {n}"
        ),
        None => 200,
    };
    // `body` (inline) and `file` are mutually exclusive, mirroring the
    // error-page path/html rule.  Absent both -> an empty body.
    let inline = prop_str(node, "body");
    let file = prop_str(node, "file");
    let body = match (inline, file) {
        (Some(_), Some(_)) => bail!(
            "{name}:{line}: respond accepts only one of body=\"...\" \
             or file=\"...\""
        ),
        (Some(b), None) => RespondBody::Inline(b),
        // A relative file path resolves against the config file's
        // directory so configs stay portable regardless of CWD.
        (None, Some(f)) => {
            RespondBody::File(resolve_config_relative(name, &f))
        }
        (None, None) => RespondBody::Empty,
    };
    // Reject a malformed Content-Type now rather than silently dropping
    // the header at request time.
    let content_type = prop_str(node, "content-type");
    if let Some(ct) = &content_type {
        HeaderValue::from_str(ct).map_err(|_| {
            anyhow!(
                "{name}:{line}: respond content-type is not a valid \
                 header value: {ct:?}"
            )
        })?;
    }
    Ok(HandlerConfig::Respond {
        status,
        body,
        content_type,
    })
}

/// Resolve a possibly-relative path against the directory of the KDL
/// config file.  `name` is the config file path threaded through every
/// parser (empty under `Config::parse` in tests).  Absolute paths and
/// the empty-`name` case pass through unchanged so absolute paths and
/// inline test configs behave intuitively.
fn resolve_config_relative(name: &str, path: &str) -> String {
    let p = std::path::Path::new(path);
    if p.is_absolute() || name.is_empty() {
        return path.to_owned();
    }
    match std::path::Path::new(name).parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            dir.join(p).to_string_lossy().into_owned()
        }
        _ => path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_config_relative;

    #[test]
    fn absolute_path_passes_through() {
        assert_eq!(
            resolve_config_relative("/etc/hypershunt.kdl", "/var/x.html"),
            "/var/x.html"
        );
    }

    #[test]
    fn relative_joins_config_dir() {
        assert_eq!(
            resolve_config_relative("/etc/hypershunt.kdl", "maint.html"),
            "/etc/maint.html"
        );
        assert_eq!(
            resolve_config_relative("/etc/hs/site.kdl", "pages/503.html"),
            "/etc/hs/pages/503.html"
        );
    }

    #[test]
    fn empty_name_passes_through() {
        // Config::parse (tests) supplies an empty name -> keep the path
        // as-is, resolved relative to CWD like every other path.
        assert_eq!(resolve_config_relative("", "maint.html"), "maint.html");
    }

    #[test]
    fn bare_config_name_has_no_dir() {
        // A config named without a directory component -> nothing to
        // prefix, so the path is unchanged.
        assert_eq!(
            resolve_config_relative("hypershunt.kdl", "maint.html"),
            "maint.html"
        );
    }
}

