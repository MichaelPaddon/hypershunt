// Auth-backend config-parse tests: PAM / LDAP / file / subrequest /
// JWT / OIDC plus location-level basic-auth flags.

use crate::config::*;

// -- auth backend ----------------------------------------------

#[test]
fn server_auth_pam_default_service() {
    let cfg = Config::parse(
        r#"
        server {
            auth "pam"
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
    assert!(matches!(
        cfg.server.auth,
        Some(AuthBackend::Pam { service, .. })
            if service == "login"
    ));
}

#[test]
fn server_auth_pam_explicit_service() {
    let cfg = Config::parse(
        r#"
        server {
            auth "pam" service="hypershunt"
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
    assert!(matches!(
        cfg.server.auth,
        Some(AuthBackend::Pam { service, .. })
            if service == "hypershunt"
    ));
}

#[test]
fn server_auth_file_block_form() {
    let cfg = Config::parse(
        r#"
        server {
            auth "file" path="/etc/hypershunt/htpasswd" cache=30
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let Some(AuthBackend::File(c)) = &cfg.server.auth {
        assert_eq!(c.path, "/etc/hypershunt/htpasswd");
        assert_eq!(c.cache_ttl_secs, 30);
    } else {
        panic!("expected AuthBackend::File");
    }
}

#[test]
fn server_auth_file_positional_path_default_cache() {
    let cfg = Config::parse(
        r#"
        server {
            auth "file" path="/etc/hypershunt/htpasswd"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let Some(AuthBackend::File(c)) = &cfg.server.auth {
        assert_eq!(c.path, "/etc/hypershunt/htpasswd");
        assert_eq!(c.cache_ttl_secs, 60);
    } else {
        panic!("expected AuthBackend::File");
    }
}

#[test]
fn server_auth_file_missing_path_errors() {
    let err = Config::parse(
        r#"
        server { auth "file" cache=30
}
        listener "tcp://0.0.0.0:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("'path'"),
        "got: {err:#}",
    );
}

#[test]
fn server_auth_absent_is_none() {
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
    assert!(cfg.server.auth.is_none());
}

#[test]
fn server_auth_unknown_backend_is_error() {
    let result = Config::parse(
        r#"
        server {
            auth "htpasswd"
}
        listener "tcp://0.0.0.0:80"
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
fn basic_auth_block_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/admin/" {
                basic-auth realm="Admin Area"
                policy {
                    allow authenticated
                    deny code=401
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
    assert_eq!(auth.realm, "Admin Area");
}

#[test]
fn basic_auth_property_form_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/admin/" {
                basic-auth realm="Admin Area"
                policy { allow authenticated; deny code=401 }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
    assert_eq!(auth.realm, "Admin Area");
}

#[test]
fn basic_auth_default_realm() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/secure/" {
                basic-auth
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
    assert_eq!(auth.realm, "Restricted");
}

// -- LDAP auth backend -----------------------------------------

#[test]
fn server_auth_ldap_defaults() {
    let cfg = Config::parse(
        r#"
        server {
            auth "ldap" url="ldap://localhost:389" bind-dn="uid={user},ou=people,dc=example,dc=com" base-dn="ou=groups,dc=example,dc=com"
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
    if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
        assert_eq!(c.url, "ldap://localhost:389");
        assert_eq!(c.bind_dn, "uid={user},ou=people,dc=example,dc=com");
        assert_eq!(c.base_dn, "ou=groups,dc=example,dc=com");
        assert_eq!(c.group_filter, "(memberUid={user})");
        assert_eq!(c.group_attr, "cn");
        assert!(!c.starttls);
        assert_eq!(c.timeout_secs, 5);
    } else {
        panic!("expected AuthBackend::Ldap");
    }
}

#[test]
fn server_auth_ldap_explicit_options() {
    let cfg = Config::parse(
        r#"
        server {
            auth "ldap" url="ldaps://ldap.example.com:636" bind-dn="uid={user},ou=people,dc=example,dc=com" base-dn="ou=groups,dc=example,dc=com" group-filter="(member=uid={user},ou=people,dc=example,dc=com)" group-attr="cn" starttls=#false timeout=10
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
    if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
        assert_eq!(c.url, "ldaps://ldap.example.com:636");
        assert_eq!(
            c.group_filter,
            "(member=uid={user},ou=people,dc=example,dc=com)"
        );
        assert_eq!(c.timeout_secs, 10);
    } else {
        panic!("expected AuthBackend::Ldap");
    }
}

#[test]
fn server_auth_ldap_unix_socket_url() {
    let cfg = Config::parse(
        r#"
        server {
            auth "ldap" url="ldapi:///var/run/slapd/ldapi" bind-dn="uid={user},ou=people,dc=example,dc=com" base-dn="ou=groups,dc=example,dc=com"
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
    if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
        assert_eq!(c.url, "ldapi:///var/run/slapd/ldapi");
    } else {
        panic!("expected AuthBackend::Ldap");
    }
}

#[test]
fn server_auth_ldap_missing_url_is_error() {
    let result = Config::parse(
        r#"
        server {
            auth "ldap" bind-dn="uid={user},ou=people,dc=example,dc=com" base-dn="ou=groups,dc=example,dc=com"
}
        listener "tcp://0.0.0.0:80"
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
fn server_auth_ldap_missing_bind_dn_is_error() {
    let result = Config::parse(
        r#"
        server {
            auth "ldap" url="ldap://localhost:389" base-dn="ou=groups,dc=example,dc=com"
}
        listener "tcp://0.0.0.0:80"
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
fn server_auth_ldap_missing_base_dn_is_error() {
    let result = Config::parse(
        r#"
        server {
            auth "ldap" url="ldap://localhost:389" bind-dn="uid={user},ou=people,dc=example,dc=com"
}
        listener "tcp://0.0.0.0:80"
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
fn server_auth_ldap_invalid_url_scheme_is_error() {
    let result = Config::parse(
        r#"
        server {
            auth "ldap" url="http://localhost:389" bind-dn="uid={user},ou=people,dc=example,dc=com" base-dn="ou=groups,dc=example,dc=com"
}
        listener "tcp://0.0.0.0:80"
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
fn server_auth_ldap_bind_dn_without_placeholder_is_error() {
    let result = Config::parse(
        r#"
        server {
            auth "ldap" url="ldap://localhost:389" bind-dn="cn=readonly,dc=example,dc=com" base-dn="ou=groups,dc=example,dc=com"
}
        listener "tcp://0.0.0.0:80"
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
fn server_auth_ldap_starttls_parses() {
    let cfg = Config::parse(
        r#"
        server {
            auth "ldap" url="ldap://localhost:389" bind-dn="uid={user},ou=people,dc=example,dc=com" base-dn="ou=groups,dc=example,dc=com" starttls=#true
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
    if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
        assert!(c.starttls);
    } else {
        panic!("expected AuthBackend::Ldap");
    }
}

#[test]
fn server_auth_unknown_backend_error_mentions_ldap() {
    let err = Config::parse(
        r#"
        server {
            auth "kerberos"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ldap"), "error should mention 'ldap': {msg}");
}

#[test]
fn location_auth_absent_is_none() {
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
    assert!(cfg.vhosts[0].locations[0].auth.is_none());
}

