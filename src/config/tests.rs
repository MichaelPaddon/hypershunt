use super::*;
use crate::config::PolicyRuleDef;

#[test]
fn minimal_static_config() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost localhost {
            location "/" {
                static root="./public"
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners.len(), 1);
    assert_eq!(cfg.vhosts.len(), 1);
    assert_eq!(cfg.vhosts[0].name.value, "localhost");
    assert!(matches!(
        cfg.vhosts[0].locations[0].handler,
        HandlerConfig::Static { .. }
    ));
}

#[test]
fn tls_file_property_form() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "files" cert="cert.pem" key="key.pem"
}
        vhost "h" {
            location "/" {
                static root="."
            }
}
        "#,
    )
    .unwrap();
    let tls = cfg.listeners[0].tls.as_ref().unwrap();
    assert!(matches!(
        &tls.cert,
        TlsConfig::Files { cert, key }
            if cert == "cert.pem" && key == "key.pem"
    ));
}

#[test]
fn tls_file_missing_cert_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "files" key="key.pem"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("cert="), "got: {err}");
}

#[test]
fn tls_self_signed_no_args() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "self-signed"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn tls_self_signed_rejects_cert() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "self-signed" { cert "x.pem"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("self-signed"), "got: {err}");
}

#[test]
fn tls_acme_property_form() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme" email="a@b.com" { domain "example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { domains, email, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(domains, &["example.com"]);
        assert_eq!(email.as_deref(), Some("a@b.com"));
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn tls_listener() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "files" cert="cert.pem" key="key.pem"
}
        vhost "h" {
            location "/" {
                static root="."
            }
}
        "#,
    )
    .unwrap();
    let tls = cfg.listeners[0].tls.as_ref().unwrap();
    assert!(matches!(
        &tls.cert,
        TlsConfig::Files { cert, key }
            if cert == "cert.pem" && key == "key.pem"
    ));
}

#[test]
fn tls_self_signed_default() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
}
        vhost "h" {
            location "/" {
                static root="."
            }
}
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn tls_explicit_self_signed() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
}
        vhost "h" {
            location "/" {
                static root="."
            }
}
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn tls_acme() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme" {
                domain "example.com"
}
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::Acme { .. }
    ));
}

#[test]
fn acme_multi_domain_parses() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  email="a@b.com" {
                domain "example.com"
                domain "www.example.com"
                domain "api.example.com"
}
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme {
        domains,
        email,
        staging,
        name,
        ..
    } = &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(
            domains,
            &["example.com", "www.example.com", "api.example.com"]
        );
        assert_eq!(email.as_deref(), Some("a@b.com"));
        assert!(!staging);
        assert!(name.is_none());
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_domain_variadic_form() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  email="a@b.com" {
domain "a.com"
domain "b.com"
domain "c.com"
}
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { domains, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(domains, &["a.com", "b.com", "c.com"]);
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_explicit_name() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  name="my-cert" {
                domain "example.com"
                domain "www.example.com"
}
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { name, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(name.as_deref(), Some("my-cert"));
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_requires_domain() {
    let result = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"
}
        vhost "h" {
            location "/" {
                static root="."
            }
}
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn acme_requires_state_dir() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "acme" {
                domain "example.com"
}
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn acme_staging_defaults_false() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme" {
                domain "example.com"
}
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { staging, .. } =
        cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert!(!staging);
    }
}

#[test]
fn tls_missing_key_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "files" cert="cert.pem"
}
        vhost "h" {
            location "/" {
                static root="."
            }
}
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn index_files_default() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { index_files, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(index_files, &["index.html", "index.htm"]);
    }
}

#[test]
fn index_files_variadic_form() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="." {
index-file "a.html"
index-file "b.html"
index-file "c.html"
}
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { index_files, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(index_files, &["a.html", "b.html", "c.html"]);
    } else {
        panic!("expected Static handler");
    }
}

#[test]
fn index_files_mixed_forms() {
    // Repeated nodes and variadic args may be combined.
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="." {
index-file "a.html"
index-file "b.html"
                    index-file "c.html"
}
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { index_files, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(index_files, &["a.html", "b.html", "c.html"]);
    } else {
        panic!("expected Static handler");
    }
}

#[test]
fn index_files_custom() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="." {
index-file "start.html"
}
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { index_files, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(index_files, &["start.html"]);
    }
}

#[test]
fn multiple_handler_types() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/static/" {
                static root="/var/www"
            }
            location "/api/" {
                proxy {
 upstream "http://127.0.0.1:3000";
}
            }
            location "/old/" {
                redirect to="/new/" code=301
            }
            location "/php/" {
                fastcgi socket="unix:/run/php/fpm.sock" root="/var/www/html"
            }
        }
        "#,
    )
    .unwrap();
    let locs = &cfg.vhosts[0].locations;
    assert!(matches!(locs[0].handler, HandlerConfig::Static { .. }));
    assert!(matches!(locs[1].handler, HandlerConfig::Proxy { .. }));
    assert!(matches!(locs[2].handler, HandlerConfig::Redirect { .. }));
    assert!(matches!(locs[3].handler, HandlerConfig::FastCgi { .. }));
}

// -- stream listener (proxy child) --------------------------------

#[test]
fn listener_proxy_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432" proxy-protocol="v2"
}
        "#,
    )
    .unwrap();
    let l = &cfg.listeners[0];
    assert_eq!(l.bind.to_url(), "tcp://[::]:5432");
    let s = l.proxy.as_ref().unwrap();
    assert_eq!(s.upstream.to_url(), "tcp://127.0.0.1:5432");
    assert_eq!(s.proxy_protocol, Some(ProxyProtocolVersion::V2));
}

#[test]
fn listener_proxy_without_proxy_protocol() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:3306" {
            proxy "tcp://127.0.0.1:3306"
}
        "#,
    )
    .unwrap();
    assert!(
        cfg.listeners[0]
            .proxy
            .as_ref()
            .unwrap()
            .proxy_protocol
            .is_none()
    );
}

#[test]
fn listener_proxy_v1_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80" {
            proxy "tcp://127.0.0.1:80" proxy-protocol="v1"
}
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].proxy.as_ref().unwrap().proxy_protocol,
        Some(ProxyProtocolVersion::V1)
    );
}

#[test]
fn proxy_protocol_bad_value_rejected() {
    for bad in ["1", "2", "v3", "V2"] {
        let src = format!(
            r#"
            listener "tcp://[::]:80" {{
                proxy "tcp://127.0.0.1:80" proxy-protocol="{bad}"
            }}
            "#
        );
        let err = Config::parse(&src).unwrap_err().to_string();
        assert!(
            err.contains("expected 'v1' or 'v2'"),
            "expected error for {bad:?}, got: {err}"
        );
    }
}

// -- accept-proxy-protocol on HTTP listeners ----------------------

#[test]
fn listener_accept_proxy_protocol_v2_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" accept-proxy-protocol="v2"
        vhost "h" { location "/" { static root="/srv" } }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].accept_proxy_protocol,
        Some(ProxyProtocolVersion::V2)
    );
    assert!(cfg.listeners[0].trusted_proxies.is_empty());
}

#[test]
fn listener_accept_proxy_protocol_v1_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" accept-proxy-protocol="v1"
        vhost "h" { location "/" { static root="/srv" } }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].accept_proxy_protocol,
        Some(ProxyProtocolVersion::V1)
    );
}

#[test]
fn listener_accept_proxy_protocol_bad_value_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" accept-proxy-protocol="v3"
        vhost "h" { location "/" { static root="/srv" } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("expected 'v1' or 'v2'"), "got: {err}");
}

#[test]
fn listener_trusted_proxies_parses_cidrs_and_bare_ips() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" accept-proxy-protocol="v2" {
            trusted-proxies "10.0.0.0/8"
trusted-proxies "192.168.1.1"
trusted-proxies "::1"
}
        vhost "h" { location "/" { static root="/srv" } }
        "#,
    )
    .unwrap();
    let nets = &cfg.listeners[0].trusted_proxies;
    assert_eq!(nets.len(), 3);
    let any = |s: &str| nets.iter().any(|n| n.to_string() == s);
    assert!(any("10.0.0.0/8"));
    // bare IP gets the host-mask
    assert!(any("192.168.1.1/32"));
    assert!(any("::1/128"));
}

#[test]
fn listener_trusted_proxies_requires_accept_proxy_protocol() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            trusted-proxies "10.0.0.0/8"
}
        vhost "h" { location "/" { static root="/srv" } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("requires 'accept-proxy-protocol'"),
        "got: {err}"
    );
}

#[test]
fn listener_trusted_proxies_rejects_invalid_cidr() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" accept-proxy-protocol="v2" {
            trusted-proxies "not-an-ip"
}
        vhost "h" { location "/" { static root="/srv" } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("invalid IP address or CIDR"), "got: {err}");
}

#[test]
fn listener_trusted_proxies_empty_list_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" accept-proxy-protocol="v2" {
            trusted-proxies
}
        vhost "h" { location "/" { static root="/srv" } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("trusted-proxies"),
        "got: {err}"
    );
}

#[test]
fn stream_listener_trusted_proxies_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" accept-proxy-protocol="v2" {
            trusted-proxies "10.0.0.0/8"
            proxy "tcp://127.0.0.1:5432"
}
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].accept_proxy_protocol,
        Some(ProxyProtocolVersion::V2)
    );
    assert_eq!(cfg.listeners[0].trusted_proxies.len(), 1);
}

#[test]
fn listener_proxy_with_tls_termination() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
            proxy "tcp://127.0.0.1:5432"
}
        "#,
    )
    .unwrap();
    let l = &cfg.listeners[0];
    assert!(l.tls.is_some());
    assert_eq!(
        l.proxy.as_ref().unwrap().upstream.to_url(),
        "tcp://127.0.0.1:5432"
    );
}

#[test]
fn listener_proxy_with_tls_and_proxy_protocol() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
            proxy "tcp://127.0.0.1:5432" proxy-protocol="v2"
}
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].proxy.as_ref().unwrap().proxy_protocol,
        Some(ProxyProtocolVersion::V2)
    );
}

#[test]
fn listener_proxy_only_needs_no_vhost() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
}
        "#,
    )
    .unwrap();
    assert!(cfg.vhosts.is_empty());
    assert_eq!(cfg.listeners.len(), 1);
    assert!(cfg.listeners[0].proxy.is_some());
}

#[test]
fn listener_proxy_unix_upstream() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "unix-stream:/run/pg.sock"
}
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].proxy.as_ref().unwrap().upstream.to_url(),
        "unix-stream:/run/pg.sock"
    );
}

#[test]
fn listener_proxy_upstream_tls_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432" {
tls
}
}
        "#,
    )
    .unwrap();
    let ut = cfg.listeners[0]
        .proxy
        .as_ref()
        .unwrap()
        .upstream_tls
        .as_ref()
        .unwrap();
    assert!(!ut.skip_verify);
}

#[test]
fn listener_proxy_upstream_tls_skip_verify_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432" {
tls skip-verify=#true
}
}
        "#,
    )
    .unwrap();
    let ut = cfg.listeners[0]
        .proxy
        .as_ref()
        .unwrap()
        .upstream_tls
        .as_ref()
        .unwrap();
    assert!(ut.skip_verify);
}

// (proxy-listener rejection of HTTP-only vhost options is covered by
// `proxy_listener_rejects_vhost_list` and
// `proxy_listener_rejects_reject_unknown_host`.)

#[test]
fn listener_http_policy_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80" {
            policy {
                allow address "10.0.0.0/8"
            }
}
        vhost "h" {
            location "/" { static root="." }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("only valid for stream listeners"),
        "expected error, got: {err}"
    );
}

#[test]
fn listener_proxy_policy_address_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
            policy {
                allow address "10.0.0.0/8"
                deny code=403
            }
}
        "#,
    )
    .unwrap();
    let stmts = cfg.listeners[0]
        .proxy
        .as_ref()
        .unwrap()
        .policy
        .as_ref()
        .unwrap();
    assert_eq!(stmts.len(), 2);
    // No country predicates present.
    assert!(stmts.iter().all(|s| match s {
        PolicyRuleDef::Rule { predicate, .. } => {
            predicate.as_ref().is_none_or(|p| !p.needs_geoip())
        }
        _ => true,
    }));
}

#[test]
fn geoip_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip db="/etc/hypershunt/GeoLite2-Country.mmdb"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.server.geoip.as_ref().unwrap().db,
        "/etc/hypershunt/GeoLite2-Country.mmdb"
    );
}

#[test]
fn geoip_block_form_still_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip db="/dev/null"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.geoip.as_ref().unwrap().db, "/dev/null");
}

#[test]
fn listener_proxy_policy_country_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip db="/dev/null"
}
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
            policy {
                allow country US CA
                deny code=403
            }
}
        "#,
    )
    .unwrap();
    let stmts = cfg.listeners[0]
        .proxy
        .as_ref()
        .unwrap()
        .policy
        .as_ref()
        .unwrap();
    assert!(stmts.iter().any(|s| match s {
        PolicyRuleDef::Rule { predicate, .. } => {
            predicate.as_ref().is_some_and(|p| p.needs_geoip())
        }
        _ => false,
    }));
}

#[test]
fn listener_proxy_access_absent_means_none() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
}
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].proxy.as_ref().unwrap().policy.is_none());
}

#[test]
fn listener_proxy_access_rejects_user_condition() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
            policy {
                allow user alice
            }
}
        "#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not supported in stream listener"),
        "unexpected error: {err}"
    );
}

#[test]
fn listener_proxy_policy_rejects_group_predicate() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
            policy {
                allow group admins
            }
}
        "#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not supported in stream listener"),
        "unexpected error: {err}"
    );
}

#[test]
fn listener_proxy_policy_rejects_authenticated_predicate() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
            policy {
                allow authenticated
            }
}
        "#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not supported in stream listener"),
        "unexpected error: {err}"
    );
}

#[test]
fn status_handler_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/status" {
                status
            }
        }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.vhosts[0].locations[0].handler,
        HandlerConfig::Status
    ));
}

#[test]
fn scgi_handler_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                scgi socket="unix-stream:/run/myapp.sock" root="/var/www/html" index="index.py"
            }
        }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.vhosts[0].locations[0].handler,
        HandlerConfig::Scgi { .. }
    ));
    if let HandlerConfig::Scgi {
        socket,
        root,
        index,
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(socket, "unix-stream:/run/myapp.sock");
        assert_eq!(root, "/var/www/html");
        assert_eq!(index.as_deref(), Some("index.py"));
    }
}

#[test]
fn cgi_handler_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/cgi-bin/" {
                cgi root="/usr/lib/cgi-bin"
            }
        }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.vhosts[0].locations[0].handler,
        HandlerConfig::Cgi { .. }
    ));
    if let HandlerConfig::Cgi { root } = &cfg.vhosts[0].locations[0].handler {
        assert_eq!(root, "/usr/lib/cgi-bin");
    }
}

#[test]
fn listener_bind_positional_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:8080"
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind.to_url(), "tcp://[::]:8080");
}

#[test]
fn listener_bind_positional_with_block() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind.to_url(), "tcp://[::]:443");
    assert!(cfg.listeners[0].tls.is_some());
}

#[test]
fn listener_proxy_bind_positional_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:5432" {
            proxy "tcp://127.0.0.1:5432"
}
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind.to_url(), "tcp://[::]:5432");
    assert_eq!(
        cfg.listeners[0].proxy.as_ref().unwrap().upstream.to_url(),
        "tcp://127.0.0.1:5432"
    );
}

#[test]
fn static_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="/var/www" strip-prefix=#true
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static {
        root, strip_prefix, ..
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(root.as_deref(), Some("/var/www"));
        assert!(*strip_prefix);
    } else {
        panic!("expected Static handler");
    }
}

#[test]
fn proxy_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/api/" {
                proxy strip-prefix=#true {
                    upstream "http://localhost:3000"
                }
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Proxy {
        upstreams,
        strip_prefix,
        ..
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(upstreams.len(), 1);
        assert_eq!(upstreams[0].url, "http://localhost:3000");
        assert_eq!(upstreams[0].weight, 1);
        assert!(*strip_prefix);
    } else {
        panic!("expected Proxy handler");
    }
}

#[test]
fn redirect_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/old/" {
                redirect to="https://example.com/new/" code=302
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Redirect { to, code } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(to, "https://example.com/new/");
        assert_eq!(*code, 302);
    } else {
        panic!("expected Redirect handler");
    }
}

#[test]
fn respond_inline_body_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/health" {
                respond status=200 body="OK\n" content-type="text/plain"
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Respond {
        status,
        body,
        content_type,
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(*status, 200);
        assert!(matches!(body, RespondBody::Inline(b) if b == "OK\n"));
        assert_eq!(content_type.as_deref(), Some("text/plain"));
    } else {
        panic!("expected Respond handler");
    }
}

#[test]
fn respond_bare_defaults_to_200_empty() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/ping" { respond }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Respond {
        status,
        body,
        content_type,
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(*status, 200);
        assert!(matches!(body, RespondBody::Empty));
        assert!(content_type.is_none());
    } else {
        panic!("expected Respond handler");
    }
}

#[test]
fn respond_body_and_file_together_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/x" { respond body="hi" file="x.html" }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("only one of"), "got: {err}");
}

#[test]
fn respond_out_of_range_status_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/x" { respond status=799 }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("status must be"), "got: {err}");
}

#[test]
fn respond_invalid_content_type_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/x" { respond body="hi" content-type="bad\nvalue" }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("content-type"), "got: {err}");
}

#[test]
fn fastcgi_property_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/php/" {
                fastcgi socket="unix:/run/php.sock" root="/var/www" index=index.php
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::FastCgi {
        socket,
        root,
        index,
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(socket, "unix:/run/php.sock");
        assert_eq!(root, "/var/www");
        assert_eq!(index.as_deref(), Some("index.php"));
    } else {
        panic!("expected FastCgi handler");
    }
}

#[test]
fn scgi_property_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/scgi/" {
                scgi socket="127.0.0.1:9000" root="/var/www"
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Scgi {
        socket,
        root,
        index,
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(socket, "127.0.0.1:9000");
        assert_eq!(root, "/var/www");
        assert!(index.is_none());
    } else {
        panic!("expected Scgi handler");
    }
}

#[test]
fn cgi_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/cgi-bin/" {
                cgi root="/usr/lib/cgi-bin"
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Cgi { root } = &cfg.vhosts[0].locations[0].handler {
        assert_eq!(root, "/usr/lib/cgi-bin");
    } else {
        panic!("expected Cgi handler");
    }
}

#[test]
fn aliases() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost example.com {
            alias www.example.com
            alias example.net
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.vhosts[0]
            .aliases
            .iter()
            .map(|a| a.value.as_str())
            .collect::<Vec<_>>(),
        ["www.example.com", "example.net"]
    );
}

// (a listener referencing an undefined vhost is covered by
// `listener_vhost_reference_must_resolve`.)

#[test]
fn redirect_default_code() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/old/" {
                redirect to="/new/"
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Redirect { code, .. } =
        cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(code, 301);
    }
}

#[test]
fn listener_bind_child_node() {
    // `bind` can appear as a child node (alternative to positional arg).
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let l = &cfg.listeners[0];
    assert_eq!(l.bind.to_url(), "tcp://0.0.0.0:8080");
    assert_eq!(l.local_name(), "tcp://0.0.0.0:8080");
}

#[test]
fn validate_rejects_missing_bind() {
    let result = Config::parse(
        r#"
        listener {
            vhost "h"
        }
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn tls_options_per_listener() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed" min-version="1.3" {
                cipher "TLS13_AES_256_GCM_SHA384"
                cipher "TLS13_CHACHA20_POLY1305_SHA256"
}
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let opts = &cfg.listeners[0].tls.as_ref().unwrap().options;
    assert!(matches!(opts.min_version, Some(TlsVersion::Tls13)));
    assert_eq!(
        opts.ciphers,
        ["TLS13_AES_256_GCM_SHA384", "TLS13_CHACHA20_POLY1305_SHA256"]
    );
}

#[test]
fn tls_options_global_defaults() {
    let cfg = Config::parse(
        r#"
        server {
            workers 2
            tls-options min-version="1.2" {
                cipher "TLS13_AES_256_GCM_SHA384"
}
}
        listener "tcp://[::]:443" {
            tls "self-signed"
}
        vhost "h" {
            location "/" {
                static root="."
            }
}
        "#,
    )
    .unwrap();
    let defaults = &cfg.server.tls_defaults;
    assert!(matches!(defaults.min_version, Some(TlsVersion::Tls12)));
    assert_eq!(defaults.ciphers, ["TLS13_AES_256_GCM_SHA384"]);
}

#[test]
fn tls_options_resolve_inheritance() {
    let global = TlsOptions {
        min_version: Some(TlsVersion::Tls12),
        ciphers: vec!["TLS13_AES_256_GCM_SHA384".into()],
    };
    // Listener overrides min_version but not ciphers.
    let per_listener = TlsOptions {
        min_version: Some(TlsVersion::Tls13),
        ciphers: vec![],
    };
    let resolved = per_listener.resolve(&global);
    assert!(matches!(resolved.min_version, Some(TlsVersion::Tls13)));
    // Falls back to global ciphers since listener has none.
    assert_eq!(resolved.ciphers, ["TLS13_AES_256_GCM_SHA384"]);
}

#[test]
fn tls_version_invalid() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed" min-version="1.1"
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

// -- per-listener vhost scoping (parsing) -----------------------

#[test]
fn listener_vhost_list_absent_is_implicit() {
    // No `vhost` child -> empty list (the implicit, all-vhosts set);
    // unknown hosts fall back to a default (reject flag off).
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "first.com" { location "/" { static root="." } }
        vhost "second.com" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].vhosts.is_empty());
    assert!(!cfg.listeners[0].reject_unknown_host);
}

#[test]
fn listener_vhost_list_parsed_in_order() {
    // Multiple `vhost` children concatenate, preserving order.
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" {
            vhost "a.com" "b.com"
            vhost "c.com"
        }
        vhost "a.com" { location "/" { static root="." } }
        vhost "b.com" { location "/" { static root="." } }
        vhost "c.com" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].vhosts, ["a.com", "b.com", "c.com"]);
}

#[test]
fn reject_unknown_host_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" reject-unknown-host=#true
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].reject_unknown_host);
}

#[test]
fn vhost_name_and_explicit_only_parse() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" { vhost "lan" "hidden" }
        vhost "example.com" name="lan" { location "/" { static root="." } }
        vhost "admin" name="hidden" explicit-only=#true {
            location "/" { static root="." }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.vhosts[0].ref_name.as_deref(), Some("lan"));
    assert!(!cfg.vhosts[0].explicit_only);
    assert_eq!(cfg.vhosts[1].ref_name.as_deref(), Some("hidden"));
    assert!(cfg.vhosts[1].explicit_only);
}

#[test]
fn vhost_reference_inside_listener_rejects_block() {
    // A listener `vhost` is a reference, not a definition.
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" {
            vhost "x" { location "/" { static root="." } }
        }
        vhost "x" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("cannot have a block"),
        "expected reference-with-block rejection, got: {err}"
    );
}

#[test]
fn listener_vhost_reference_must_resolve() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" { vhost "nope" }
        vhost "real.com" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("unknown vhost 'nope'"),
        "expected unknown-vhost error, got: {err}"
    );
}

#[test]
fn duplicate_vhost_handle_rejected() {
    // Two vhosts default their handle to the same host pattern.
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "example.com" { location "/" { static root="." } }
        vhost "example.com" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("duplicate vhost handle 'example.com'"),
        "expected duplicate-handle error, got: {err}"
    );
}

#[test]
fn same_host_two_vhosts_on_one_listener_rejected() {
    // Distinct handles (lan/pub) so the vhosts are legal globally, but
    // serving the same literal host twice on one listener is ambiguous.
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" { vhost "lan" "pub" }
        vhost "example.com" name="lan" { location "/" { static root="." } }
        vhost "example.com" name="pub" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("served by more than one vhost"),
        "expected per-listener host collision error, got: {err}"
    );
}

#[test]
fn proxy_listener_rejects_vhost_list() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:5432" {
            vhost "x"
            proxy "tcp://127.0.0.1:5432"
        }
        vhost "x" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("'vhost' is only valid in HTTP listeners"),
        "expected proxy vhost rejection, got: {err}"
    );
}

#[test]
fn proxy_listener_rejects_reject_unknown_host() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:5432" reject-unknown-host=#true {
            proxy "tcp://127.0.0.1:5432"
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("'reject-unknown-host' is only valid in HTTP"),
        "expected proxy reject-unknown-host rejection, got: {err}"
    );
}

// -- timeouts --------------------------------------------------

#[test]
fn timeouts_parse() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" {
            timeouts request-header=30 handler=60 keepalive=75
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let t = &cfg.listeners[0].timeouts;
    assert_eq!(t.request_header_secs, Some(30));
    assert_eq!(t.handler_secs, Some(60));
    assert_eq!(t.keepalive_secs, Some(75));
}

#[test]
fn timeouts_defaults_to_none() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let t = &cfg.listeners[0].timeouts;
    assert!(t.request_header_secs.is_none());
    assert!(t.handler_secs.is_none());
    assert!(t.keepalive_secs.is_none());
}

#[test]
fn timeouts_partial() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" {
            timeouts handler=120
}
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let t = &cfg.listeners[0].timeouts;
    assert!(t.request_header_secs.is_none());
    assert_eq!(t.handler_secs, Some(120));
    assert!(t.keepalive_secs.is_none());
}

#[test]
fn timeouts_property_form() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" {
            timeouts request-header=30 handler=60 keepalive=75
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    let t = &cfg.listeners[0].timeouts;
    assert_eq!(t.request_header_secs, Some(30));
    assert_eq!(t.handler_secs, Some(60));
    assert_eq!(t.keepalive_secs, Some(75));
}

// -- server user/group -----------------------------------------

#[test]
fn access_log_block_parses_json_format() {
    use crate::config::AccessLogFormatConfig;
    let cfg = Config::parse(
        r#"
        server {
            access-log "json" path="/var/log/hypershunt/access.log"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    let al = cfg.server.access_log.as_ref().expect("present");
    assert_eq!(al.format, AccessLogFormatConfig::Json);
    assert_eq!(al.path.as_deref(), Some("/var/log/hypershunt/access.log"));
}

#[test]
fn access_log_block_defaults_path_to_none() {
    use crate::config::AccessLogFormatConfig;
    let cfg = Config::parse(
        r#"
        server {
            access-log "common"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    let al = cfg.server.access_log.as_ref().expect("present");
    assert_eq!(al.format, AccessLogFormatConfig::Common);
    assert!(al.path.is_none());
}

#[test]
fn access_log_accepts_combined_and_tracing() {
    use crate::config::AccessLogFormatConfig;
    for (s, expected) in [
        ("combined", AccessLogFormatConfig::Combined),
        ("tracing", AccessLogFormatConfig::Tracing),
    ] {
        let cfg = Config::parse(&format!(
            r#"
            server {{ access-log "{s}" }}
            listener "tcp://0.0.0.0:80" {{ }}
            vhost "h" {{ location "/" {{ static root="." }} }}
            "#
        ))
        .unwrap();
        assert_eq!(
            cfg.server.access_log.as_ref().unwrap().format,
            expected,
            "format {s} should parse",
        );
    }
}

#[test]
fn access_log_rejects_unknown_format() {
    let err = Config::parse(
        r#"
        server { access-log "binary"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("unknown access-log format"),
        "got error: {err}"
    );
}

#[test]
fn access_log_requires_format() {
    let err = Config::parse(
        r#"
        server { access-log { path "/tmp/a.log" }
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("requires a format"),
        "got error: {err}"
    );
}

#[test]
fn access_log_absent_defaults_to_none() {
    let cfg = Config::parse(
        r#"
        server user="nobody"
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(cfg.server.access_log.is_none());
}

#[test]
fn server_user_and_group_parse() {
    let cfg = Config::parse(
        r#"
        server user="nobody" group="nogroup"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.user.as_deref(), Some("nobody"));
    assert_eq!(cfg.server.group.as_deref(), Some("nogroup"));
}

#[test]
fn server_user_only_parses() {
    let cfg = Config::parse(
        r#"
        server user="www-data"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.user.as_deref(), Some("www-data"));
    assert!(cfg.server.group.is_none());
}

#[test]
fn inherit_supplementary_groups_parses() {
    let cfg = Config::parse(
        r#"
        server user="hypershunt" inherit-supplementary-groups=#true
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert!(cfg.server.inherit_supplementary_groups);
}

#[test]
fn inherit_supplementary_groups_defaults_false() {
    let cfg = Config::parse(
        r#"
        server user="hypershunt"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert!(!cfg.server.inherit_supplementary_groups);
}

// -- health config ---------------------------------------------

#[test]
fn health_enabled_by_default() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert!(cfg.server.health.enabled);
}

#[test]
fn health_explicit_enabled_true() {
    let cfg = Config::parse(
        r#"
        server {
            health
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert!(cfg.server.health.enabled);
}

#[test]
fn health_explicit_enabled_false() {
    let cfg = Config::parse(
        r#"
        server {
            health enabled=#false
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    assert!(!cfg.server.health.enabled);
}

#[test]
fn health_positional_bool_false() {
    let cfg = Config::parse(
        r#"
        server {
            health enabled=#false
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(!cfg.server.health.enabled);
}

#[test]
fn health_positional_bool_true() {
    let cfg = Config::parse(
        r#"
        server {
            health
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(cfg.server.health.enabled);
}

#[test]
fn health_default_paths() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.health.liveness_paths, ["/healthz", "/livez"]);
    assert_eq!(cfg.server.health.readiness_paths, ["/readyz"]);
}

#[test]
fn health_custom_paths_override_defaults() {
    let cfg = Config::parse(
        r#"
        server {
            health {
                liveness-path "/alive"
                readiness-path "/ready"
                readiness-path "/ready2"
            }
        }
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.health.liveness_paths, ["/alive"]);
    assert_eq!(cfg.server.health.readiness_paths, ["/ready", "/ready2"]);
}

#[test]
fn health_path_must_be_absolute() {
    let err = Config::parse(
        r#"
        server { health { liveness-path "alive" } }
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("must start with '/'"),
        "expected absolute-path error, got: {err}"
    );
}

#[test]
fn health_path_liveness_readiness_overlap_rejected() {
    let err = Config::parse(
        r#"
        server {
            health {
                liveness-path "/healthz"
                readiness-path "/healthz"
            }
        }
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("both liveness and readiness"),
        "expected overlap error, got: {err}"
    );
}

#[test]
fn listener_health_override_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80" health=#false
        listener "tcp://0.0.0.0:8080" health=#true
        listener "tcp://0.0.0.0:9090"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].health, Some(false));
    assert_eq!(cfg.listeners[1].health, Some(true));
    assert_eq!(cfg.listeners[2].health, None);
}

#[test]
fn lame_duck_timeout_parses() {
    let cfg = Config::parse(
        r#"
        server lame-duck-timeout=5
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.lame_duck_timeout, 5);
}

#[test]
fn lame_duck_timeout_defaults_zero() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.lame_duck_timeout, 0);
}

#[test]
fn proxy_listener_rejects_health() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:5432" health=#false {
            proxy "tcp://127.0.0.1:5432"
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("'health' is only valid in HTTP listeners"),
        "expected proxy health rejection, got: {err}"
    );
}

// -- request-headers / response-headers parsing ---------------

#[test]
fn request_headers_set_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                request-headers {
                    set "X-Client-IP" "{client_ip}"
                }
                static root="."
            }
        }
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].request_headers;
    assert_eq!(ops.len(), 1);
    assert!(matches!(&ops[0], HeaderOpConfig::Set { name, value }
        if name == "X-Client-IP" && value == "{client_ip}"));
}

#[test]
fn request_headers_add_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                request-headers {
                    add "Vary" "accept"
                }
                static root="."
            }
        }
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].request_headers;
    assert!(matches!(&ops[0], HeaderOpConfig::Add { .. }));
}

#[test]
fn request_headers_remove_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                request-headers {
                    remove "Authorization"
                }
                static root="."
            }
        }
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].request_headers;
    assert!(matches!(&ops[0],
        HeaderOpConfig::Remove { name } if name == "Authorization"));
}

#[test]
fn response_headers_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                response-headers {
                    set "X-Frame-Options" "DENY"
                }
                static root="."
            }
        }
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].response_headers;
    assert_eq!(ops.len(), 1);
    assert!(matches!(&ops[0],
        HeaderOpConfig::Set { name, value }
            if name == "X-Frame-Options" && value == "DENY"));
}

#[test]
fn header_rules_absent_means_empty_vecs() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
    "#,
    )
    .unwrap();
    assert!(cfg.vhosts[0].locations[0].request_headers.is_empty());
    assert!(cfg.vhosts[0].locations[0].response_headers.is_empty());
}

#[test]
fn invalid_header_name_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                request-headers {
                    set "not valid!" "value"
                }
                static root="."
            }
        }
    "#,
    );
    assert!(result.is_err());
}

#[test]
fn unknown_op_in_request_headers_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                request-headers {
                    prepend "X-Foo" "bar"
                }
                static root="."
            }
        }
    "#,
    );
    assert!(result.is_err());
}

// -- Unix domain socket listener tests --------------------------------

#[test]
#[cfg(unix)]
fn unix_socket_bind_parses() {
    let cfg = Config::parse(
        r#"
        listener "unix-stream:/run/hypershunt.sock"
        vhost "h" {
            location "/" { static root="." }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind.to_url(), "unix-stream:/run/hypershunt.sock");
}

#[test]
#[cfg(unix)]
fn unix_socket_empty_path_is_error() {
    // Strict URL grammar: an empty path under any unix-* scheme is a
    // parse error caught by the bind-URL parser.
    let result = Config::parse(
        r#"
        listener "unix-stream:"
        vhost "h" {
            location "/" { static root="." }
        }
        "#,
    );
    let err = format!("{:#}", result.unwrap_err());
    assert!(err.contains("must not be empty"), "got: {err}");
}

// -- Proxy handler proxy-protocol tests -------------------------------

#[test]
fn proxy_handler_proxy_protocol_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                proxy proxy-protocol="v1" {
                    upstream "http://backend:8080"
                }
            }
        }
        "#,
    )
    .unwrap();
    let loc = &cfg.vhosts[0].locations[0];
    assert!(matches!(
        loc.handler,
        HandlerConfig::Proxy {
            proxy_protocol: Some(ProxyProtocolVersion::V1),
            ..
        }
    ));
}

#[test]
fn proxy_handler_proxy_protocol_v2_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                proxy proxy-protocol="v2" {
                    upstream "http://backend:8080"
                }
            }
        }
        "#,
    )
    .unwrap();
    let loc = &cfg.vhosts[0].locations[0];
    assert!(matches!(
        loc.handler,
        HandlerConfig::Proxy {
            proxy_protocol: Some(ProxyProtocolVersion::V2),
            ..
        }
    ));
}

#[test]
fn auth_request_handler_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/auth" {
                auth-request
            }
        }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.vhosts[0].locations[0].handler,
        HandlerConfig::AuthRequest
    ));
}

#[test]
fn auth_subrequest_minimal_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        server {
            auth "subrequest" url="http://auth.internal/check"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    match cfg.server.auth.as_ref().unwrap() {
        AuthBackend::Subrequest(c) => {
            assert_eq!(c.url, "http://auth.internal/check");
            assert!(c.forward_headers.is_empty());
            assert!(c.user_header.is_none());
            assert!(c.groups_header.is_none());
            assert_eq!(c.timeout_secs, 5); // default
        }
        other => panic!("expected Subrequest, got {other:?}"),
    }
}

#[test]
fn auth_subrequest_full_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        server {
            auth "subrequest" url="http://auth.internal/check" \
                user-header="X-Auth-User" \
                groups-header="X-Auth-Groups" timeout=10 {
                forward-header "Authorization"
                forward-header "Cookie"
            }
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    match cfg.server.auth.as_ref().unwrap() {
        AuthBackend::Subrequest(c) => {
            assert_eq!(c.forward_headers, ["Authorization", "Cookie"]);
            assert_eq!(c.user_header.as_deref(), Some("X-Auth-User"));
            assert_eq!(c.groups_header.as_deref(), Some("X-Auth-Groups"));
            assert_eq!(c.timeout_secs, 10);
        }
        other => panic!("expected Subrequest, got {other:?}"),
    }
}

#[test]
fn auth_subrequest_requires_http_scheme() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        server {
            auth "subrequest" url="https://auth.internal/check"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.to_lowercase().contains("http://"),
        "expected scheme error, got: {err}"
    );
}

#[test]
fn auth_subrequest_missing_url_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        server {
            auth "subrequest"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.to_lowercase().contains("url"),
        "expected url error, got: {err}"
    );
}

// -- Syntax / semantic error reporting -----------------------------
//
// These lock in accurate line numbers (the kdl crate's KdlError does
// not expose labels(), so the offset must come from e.diagnostics) and
// the misnesting / did-you-mean / semantic-line behaviours.

#[test]
fn syntax_error_reports_correct_line() {
    // Unterminated string on line 5; must not collapse to line 1.
    let src = r#"server {}
listener "tcp://[::]:80"
vhost "a" {
    location "/" {
        static root="/tmp
    }
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(err.contains("line 5"), "expected line 5, got: {err}");
    assert!(!err.contains("line 1"), "should not say line 1: {err}");
}

#[test]
fn syntax_error_includes_snippet() {
    let src = r#"server {}
vhost "a" {
    location "/" {
        static root="/tmp
    }
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(
        err.contains("-- `") && err.contains("static root="),
        "expected source snippet, got: {err}"
    );
}

#[test]
fn syntax_error_unaffected_by_continuation() {
    // A `\` line continuation spans lines 2-3, but the actual error is
    // on physical line 5; the report must name line 5, not the logical
    // node's start.
    let src = "server {}\nlistener \\\n    \"tcp://[::]:80\"\nvhost \"a\" {\n    static root=\"/tmp\n}\n";
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(err.contains("line 5"), "expected line 5, got: {err}");
}

#[test]
fn unbalanced_brace_reports_open_line_and_is_clear() {
    // Missing one closing '}'.  kdl reports the OPENING brace line (3)
    // with a clear message.
    let src = r#"server {}
listener "tcp://[::]:80"
vhost "a" {
    location "/" {
        static root="/tmp"
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(err.contains("line 3"), "expected line 3, got: {err}");
    assert!(
        err.to_lowercase().contains("closing"),
        "expected a clear unbalanced-brace message, got: {err}"
    );
}

#[test]
fn syntax_error_non_ascii_no_panic() {
    // A multibyte char before the error must not panic the
    // offset->line slicing (char-boundary clamp).
    let src = "server {}\nvhost \"ké\" {\n    location \"/\" { static root=\"/tmp\n}\n";
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(!err.is_empty(), "expected an error, got empty");
}

#[test]
fn misnested_listener_in_server_is_diagnosed() {
    // Balanced braces, but an unclosed `server {` swallows the
    // listener.  Must name the misplaced node and its line, not emit
    // the confusing "config must define at least one listener".
    let src = r#"server {
    geoip db="/x.mmdb"

    listener "tcp://[::]:80"

    vhost "a" {
        location "/" { static root="/tmp" }
    }
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(
        err.contains("'listener' cannot be nested"),
        "expected misnesting message, got: {err}"
    );
    assert!(err.contains("line 4"), "expected line 4, got: {err}");
    assert!(
        err.contains("line 1"),
        "expected the parent block line, got: {err}"
    );
    assert!(
        !err.contains("at least one listener"),
        "should not surface the symptom error: {err}"
    );
}

#[test]
fn misnested_vhost_in_server_is_diagnosed() {
    let src = r#"server {
    geoip db="/x.mmdb"

    vhost "a" {
        location "/" { static root="/tmp" }
    }
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(
        err.contains("'vhost' cannot be nested"),
        "expected misnesting message, got: {err}"
    );
}

#[test]
fn semantic_error_carries_line() {
    // A listener that references an undefined certificate.  The error
    // must point at the listener's line (3), not be location-less.
    let src = r#"server {}
listener "tcp://[::]:80"
listener "tcp://[::]:443" {
    tls ref name="missing-cert"
}
vhost "a" {
    location "/" { static root="/tmp" }
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(
        err.contains("unknown certificate"),
        "expected cert-ref error, got: {err}"
    );
    assert!(err.contains("line 3"), "expected line 3, got: {err}");
}

#[test]
fn unknown_top_level_node_suggests_nearest() {
    let src = r#"server {}
listner "tcp://[::]:80"
vhost "a" {
    location "/" { static root="/tmp" }
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(
        err.contains("did you mean 'listener'"),
        "expected suggestion, got: {err}"
    );
}

#[test]
fn unknown_vhost_child_suggests_nearest() {
    let src = r#"server {}
listener "tcp://[::]:80"
vhost "a" {
    locaiton "/" { static root="/tmp" }
}
"#;
    let err = Config::parse(src).unwrap_err().to_string();
    assert!(
        err.contains("did you mean 'location'"),
        "expected suggestion, got: {err}"
    );
}

mod tls;

mod auth;

mod policy;
