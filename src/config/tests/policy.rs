// Policy + predicate config-parse tests.

use crate::access::{PolicyAction, Predicate};
use crate::config::*;

// -- policy blocks ---------------------------------------------

fn rule_action(s: &PolicyRuleDef) -> &PolicyAction {
    match s {
        PolicyRuleDef::Rule { action, .. } => action,
        _ => panic!("expected Rule"),
    }
}

fn rule_predicate(s: &PolicyRuleDef) -> Option<&Predicate> {
    match s {
        PolicyRuleDef::Rule { predicate, .. } => predicate.as_ref(),
        _ => panic!("expected Rule"),
    }
}

#[test]
fn policy_allow_address_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/admin/" {
                policy {
                    allow address "10.0.0.0/8"
                    deny code=403
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert_eq!(stmts.len(), 2);
    assert!(matches!(rule_action(&stmts[0]), PolicyAction::Allow));
    assert!(matches!(
        rule_action(&stmts[1]),
        PolicyAction::Deny { code: 403 }
    ));
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Address(_))
    ));
}

#[test]
fn policy_deny_custom_code_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    deny code=429 address "1.2.3.4"
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Deny { code: 429 }
    ));
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Address(_))
    ));
}

#[test]
fn policy_redirect_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    redirect to="/login/" code=302 user unverified
                    deny code=403
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Redirect { code: 302, .. }
    ));
    if let PolicyAction::Redirect { to, .. } = rule_action(&stmts[0]) {
        assert_eq!(to, "/login/");
    }
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::User(_))
    ));
}

#[test]
fn policy_empty_block_has_zero_rules() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert_eq!(stmts.len(), 0);
}

#[test]
fn policy_absent_means_none() {
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
    assert!(cfg.vhosts[0].locations[0].policy.is_none());
}

#[test]
fn policy_invalid_cidr_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow address "not-an-ip"
                }
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_unknown_statement_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    block address "1.2.3.4"
                }
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_country_without_geoip_is_error() {
    // country predicates require a geoip db at validate() time.
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow country US
                }
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_redirect_missing_to_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    redirect code=302 address "1.2.3.4"
                }
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_address_without_prefix_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow address "192.168.1.1"
                    deny code=403
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Address(_))
    ));
}

#[test]
fn policy_authenticated_predicate_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/members/" {
                policy {
                    allow authenticated
                    deny code=403
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Authenticated)
    ));
}

#[test]
fn policy_group_predicate_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/admin/" {
                policy {
                    allow group admin
                    deny code=403
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Group(g)) if g == &["admin"]
    ));
}

#[test]
fn policy_no_predicate_rule_is_catch_all() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow address "10.0.0.0/8"
                    deny code=403
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    // deny rule has no predicate -> catch-all
    assert!(rule_predicate(&stmts[1]).is_none());
}

#[test]
fn policy_country_predicate_parses() {
    // Inline multi-value country predicate.
    let cfg = Config::parse(
        r#"
        server {
            geoip db="/dev/null"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    deny country CN RU
                    allow
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert_eq!(stmts.len(), 2);
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Deny { code: 403 }
    ));
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Country(c)) if c.len() == 2
    ));
}

#[test]
fn policy_pass_action_is_error() {
    // `pass` is no longer a valid statement.
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    pass address "10.0.0.0/8"
                    deny
                }
                static root="."
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_apply_statement_parses() {
    let cfg = Config::parse(
        r#"
        server {
            policy "allow-all" {
                allow
            }
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    apply "allow-all"
                    deny
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    // Named policy stored in server config.
    assert!(cfg.server.policies.contains_key("allow-all"));
    // Inline policy block has Apply statement.
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(
        matches!(&stmts[0], PolicyRuleDef::Apply { name } if name == "allow-all")
    );
}

#[test]
fn policy_named_policy_parsed() {
    let cfg = Config::parse(
        r#"
        server {
            policy "ip-filter" {
                deny code=403 not address "10.0.0.0/8"
            }
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
    let stmts = cfg.server.policies.get("ip-filter").unwrap();
    assert_eq!(stmts.len(), 1);
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Deny { code: 403 }
    ));
    // Predicate should be Not(Address(...))
    assert!(matches!(rule_predicate(&stmts[0]), Some(Predicate::Not(_))));
}

#[test]
fn policy_duplicate_name_is_error() {
    let result = Config::parse(
        r#"
        server {
            policy "dup" {
                allow
            }
            policy "dup" {
                deny
            }
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
fn policy_old_ip_syntax_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow { ip "10.0.0.0/8" }
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("\'ip\'") || err.contains("'ip'"),
        "expected ip migration hint, got: {err}"
    );
}

#[test]
fn policy_address_multi_value_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow address "10.0.0.0/8" "192.168.0.0/16"
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::Address(nets)) => assert_eq!(nets.len(), 2),
        other => panic!("expected Address, got {other:?}"),
    }
}

#[test]
fn policy_user_multi_value_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow user alice "bob"
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::User(names)) => {
            assert_eq!(names, &["alice", "bob"]);
        }
        other => panic!("expected User, got {other:?}"),
    }
}

#[test]
fn policy_group_multi_value_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow group admin "ops"
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::Group(groups)) => {
            assert_eq!(groups, &["admin", "ops"]);
        }
        other => panic!("expected Group, got {other:?}"),
    }
}

#[test]
fn policy_not_inline_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    deny code=401 not authenticated
                    allow
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Not(inner)) if matches!(inner.as_ref(), Predicate::Authenticated)
    ));
}

#[test]
fn policy_not_in_block_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip db="/dev/null"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow { not country CN; authenticated }
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    // Block with two predicates → And
    assert!(matches!(rule_predicate(&stmts[0]), Some(Predicate::And(_))));
}

#[test]
fn policy_and_from_block_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    allow { address "10.0.0.0/8"; authenticated }
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::And(preds)) => assert_eq!(preds.len(), 2),
        other => panic!("expected And, got {other:?}"),
    }
}

#[test]
fn policy_country_in_named_policy_triggers_geoip_validation() {
    // Bug #2 regression: country inside a named policy must be caught
    // by validate() even when only referenced via apply.
    let result = Config::parse(
        r#"
        server {
            policy "geo-block" {
                deny country CN
            }
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                policy {
                    apply "geo-block"
                    allow
                }
                static root="."
            }
        }
        "#,
    );
    // No geoip configured → validate() must reject this.
    assert!(
        result.is_err(),
        "country in named policy must trigger geoip validation"
    );
}

#[test]
fn error_page_path_property_form() {
    let cfg = Config::parse(
        r#"
        server {
            error-page 403 path="/var/www/errors/403.html"
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
    assert_eq!(cfg.server.error_pages.len(), 1);
    assert_eq!(cfg.server.error_pages[0].0, 403);
    assert!(matches!(
        &cfg.server.error_pages[0].1,
        ErrorPageDef::File(p) if p == "/var/www/errors/403.html"
    ));
}

#[test]
fn error_page_legacy_positional_rejected() {
    let err = Config::parse(
        r#"
        server {
            error-page 403 "/var/www/errors/403.html"
}
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("path=") && err.contains("html="),
        "expected migration hint, got: {err}"
    );
}

#[test]
fn error_page_path_and_html_conflict_is_error() {
    let result = Config::parse(
        r#"
        server {
            error-page 404 path="/x.html" html="<h1>x</h1>"
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
fn error_page_inline_html_parses() {
    let cfg = Config::parse(
        r#"
        server {
            error-page 401 html="<h1>Please log in</h1>"
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
    assert_eq!(cfg.server.error_pages.len(), 1);
    assert!(matches!(
        &cfg.server.error_pages[0].1,
        ErrorPageDef::Inline(html) if html == "<h1>Please log in</h1>"
    ));
}

#[test]
fn error_page_missing_source_is_error() {
    let result = Config::parse(
        r#"
        server {
            error-page 404
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
fn location_no_handler_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/" {
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn redirect_302() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:80"
        vhost "h" {
            location "/temp/" {
                redirect to="/new/" code=302
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Redirect { to, code } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(code, &302u16);
        assert_eq!(to, "/new/");
    } else {
        panic!("expected Redirect handler");
    }
}

#[test]
fn server_user_defaults_to_none() {
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
    assert!(cfg.server.user.is_none());
    assert!(cfg.server.group.is_none());
}

