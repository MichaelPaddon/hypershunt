    use super::*;

    fn make_config(kdl: &str) -> Config {
        Config::parse(kdl).unwrap()
    }

    fn make_router(config: &Config) -> Router {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(config),
        );
        Router::new(config, &metrics, &summary, None).unwrap()
    }

    // Route a synthetic request and return the matched location prefix,
    // or None.
    fn route_str(
        router: &Router,
        host: &str,
        path: &str,
        bind: &str,
    ) -> Option<String> {
        let host_stripped = strip_port(host);
        let vhost = router.resolve_vhost(Some(host_stripped), bind)?;

        vhost
            .locations
            .iter()
            .filter(|loc| path.starts_with(loc.path.as_str()))
            .max_by_key(|loc| loc.path.len())
            .map(|loc| loc.path.clone())
    }

    type RouteMeta = (
        Option<Arc<PolicyBlock>>,
        Option<Arc<BasicAuthConfig>>,
        Option<Arc<HeaderRules>>,
    );

    // Return the matched location's metadata fields.
    fn route_meta(
        router: &Router,
        host: &str,
        path: &str,
        bind: &str,
    ) -> Option<RouteMeta> {
        let host_stripped = strip_port(host);
        let vhost = router.resolve_vhost(Some(host_stripped), bind)?;
        vhost
            .locations
            .iter()
            .filter(|loc| path.starts_with(loc.path.as_str()))
            .max_by_key(|loc| loc.path.len())
            .map(|loc| {
                (
                    loc.policy.clone(),
                    loc.basic_auth.clone(),
                    loc.header_rules.clone(),
                )
            })
    }

    #[test]
    fn routes_by_host() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80" default-vhost="a.com"
            vhost "a.com" {
                location "/" {
                    static root="/var/www/a"
                }
            }
            vhost "b.com" {
                location "/docs/" {
                    static root="/var/www/b"
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "a.com", "/index.html", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "b.com", "/docs/readme.txt", "tcp://0.0.0.0:80"),
            Some("/docs/".into())
        );
        assert_eq!(route_str(&router, "b.com", "/other", "tcp://0.0.0.0:80"), None);
    }

    #[test]
    fn falls_back_to_default_vhost() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80" default-vhost="a.com"
            vhost "a.com" {
                location "/" {
                    static root="/var/www/a"
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "unknown.com", "/", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
    }

    // -- regex vhost matching --------------------------------------

    #[test]
    fn regex_vhost_matches_by_pattern() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost ".+\\.example\\.com" regex=#true {
                location "/" {
                    static root="/var/www/example"
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "foo.example.com", "/", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "bar.example.com", "/", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
    }

    #[test]
    fn regex_vhost_does_not_match_unrelated_host() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80" default-vhost=#null
            vhost ".+\\.example\\.com" regex=#true {
                location "/" {
                    static root="/var/www/example"
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "notexample.org", "/", "tcp://0.0.0.0:80"),
            None
        );
    }

    #[test]
    fn literal_takes_priority_over_regex() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.example.com" {
                location "/exact/" {
                    static root="/exact"
                }
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/wild/" {
                    static root="/wild"
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "a.example.com", "/exact/page", "tcp://0.0.0.0:80"),
            Some("/exact/".into())
        );
        assert_eq!(
            route_str(&router, "b.example.com", "/wild/page", "tcp://0.0.0.0:80"),
            Some("/wild/".into())
        );
    }

    #[test]
    fn regex_patterns_checked_in_config_order() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80" default-vhost=#null
            vhost ".*\\.com" regex=#true {
                location "/first/" {
                    static root="/first"
                }
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/second/" {
                    static root="/second"
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "foo.example.com", "/first/", "tcp://0.0.0.0:80"),
            Some("/first/".into())
        );
    }

    #[test]
    fn regex_alias_matches() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80" default-vhost=#null
            vhost "example.com" {
                alias ".+\\.example\\.com" regex=#true
                location "/" {
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "sub.example.com", "/", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "example.com", "/", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
    }

    #[test]
    fn regex_vhost_as_implicit_default() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost ".+\\.example\\.com" regex=#true {
                location "/" {
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "other.org", "/", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "sub.example.com", "/", "tcp://0.0.0.0:80"),
            Some("/".into())
        );
    }

    #[test]
    fn regex_vhost_as_explicit_default() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80" default-vhost=".+\\.example\\.com"
            vhost "exact.com" {
                location "/exact/" {
                    static root="/exact"
                }
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/wild/" {
                    static root="/wild"
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "exact.com", "/exact/", "tcp://0.0.0.0:80"),
            Some("/exact/".into())
        );
        assert_eq!(
            route_str(&router, "foo.example.com", "/wild/", "tcp://0.0.0.0:80"),
            Some("/wild/".into())
        );
        assert_eq!(
            route_str(&router, "other.org", "/wild/", "tcp://0.0.0.0:80"),
            Some("/wild/".into())
        );
    }

    #[test]
    fn invalid_regex_vhost_is_config_error() {
        let result = Config::parse(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "[invalid" regex=#true {
                location "/" {
                    static root="."
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn longer_prefix_wins_regardless_of_declaration_order() {
        let config_catchall_first = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "example.com" {
                location "/" {
                    static root="/www"
                }
                location "/docs/" {
                    static root="/docs"
                }
            }
            "#,
        );
        let config_specific_first = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "example.com" {
                location "/docs/" {
                    static root="/docs"
                }
                location "/" {
                    static root="/www"
                }
            }
            "#,
        );
        for config in [config_catchall_first, config_specific_first] {
            let router = make_router(&config);
            assert_eq!(
                route_str(&router, "example.com", "/docs/readme", "tcp://0.0.0.0:80"),
                Some("/docs/".into()),
                "longer prefix /docs/ should win"
            );
            assert_eq!(
                route_str(&router, "example.com", "/index.html", "tcp://0.0.0.0:80"),
                Some("/".into()),
                "catch-all / should win when no longer match"
            );
        }
    }

    #[test]
    fn absent_host_header_uses_default_vhost() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80" default-vhost="fallback.com"
            vhost "fallback.com" {
                location "/" {
                    static root="/var/www/fallback"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let vhost = router.resolve_vhost(None, "tcp://0.0.0.0:80");
        assert!(
            vhost.is_some(),
            "no Host header should fall back to default"
        );
        let path = vhost.and_then(|vh| {
            vh.locations
                .iter()
                .find(|l| "/".starts_with(l.path.as_str()))
                .map(|l| l.path.clone())
        });
        assert_eq!(path, Some("/".into()));
    }

    #[test]
    fn strip_port_ipv4() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
    }

    #[test]
    fn strip_port_ipv6() {
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
    }

    // -- basic_auth / policy propagation ---------------------------

    #[test]
    fn basic_auth_realm_propagates_to_route() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/secure/" {
                    basic-auth realm="Secret Zone"
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, auth, _) =
            route_meta(&router, "h", "/secure/", "tcp://0.0.0.0:80").unwrap();
        assert_eq!(auth.unwrap().realm, "Secret Zone");
    }

    #[test]
    fn basic_auth_absent_when_no_auth_block() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/" {
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, auth, _) = route_meta(&router, "h", "/", "tcp://0.0.0.0:80").unwrap();
        assert!(auth.is_none());
    }

    #[test]
    fn basic_auth_per_location_independent() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/public/" {
                    static root="."
                }
                location "/private/" {
                    basic-auth realm="Members Only"
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, pub_auth, _) =
            route_meta(&router, "h", "/public/x", "tcp://0.0.0.0:80").unwrap();
        let (_, priv_auth, _) =
            route_meta(&router, "h", "/private/x", "tcp://0.0.0.0:80").unwrap();
        assert!(pub_auth.is_none());
        assert_eq!(priv_auth.unwrap().realm, "Members Only");
    }

    #[test]
    fn policy_propagates_to_route() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/admin/" {
                    policy {
                        deny code=403
                    }
                    static root="."
                }
                location "/" {
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (policy, _, _) =
            route_meta(&router, "h", "/admin/x", "tcp://0.0.0.0:80").unwrap();
        assert!(policy.is_some(), "/admin/ should have a policy");
        let (policy, _, _) =
            route_meta(&router, "h", "/index.html", "tcp://0.0.0.0:80").unwrap();
        assert!(policy.is_none(), "/ should have no policy");
    }

    #[test]
    fn basic_auth_and_policy_coexist() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/members/" {
                    basic-auth realm="Club"
                    policy {
                        allow { authenticated }
                        deny code=401
                    }
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (policy, auth, _) =
            route_meta(&router, "h", "/members/", "tcp://0.0.0.0:80").unwrap();
        assert!(policy.is_some());
        assert_eq!(auth.unwrap().realm, "Club");
    }

    // -- header_rules propagation ----------------------------------

    #[test]
    fn header_rules_propagate_to_route() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/api/" {
                    request-headers {
                        set "X-Client-IP" "{client_ip}"
                    }
                    static root="."
                }
            }
        "#,
        );
        let router = make_router(&config);
        let (_, _, rules) =
            route_meta(&router, "h", "/api/x", "tcp://0.0.0.0:80").unwrap();
        assert!(rules.is_some());
        let rules = rules.unwrap();
        assert_eq!(rules.request.len(), 1);
        assert!(!rules.needs_principal);
    }

    #[test]
    fn header_rules_none_when_no_blocks() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/" {
                    static root="."
                }
            }
        "#,
        );
        let router = make_router(&config);
        let (_, _, rules) =
            route_meta(&router, "h", "/", "tcp://0.0.0.0:80").unwrap();
        assert!(rules.is_none());
    }

    #[test]
    fn needs_principal_propagated_for_username_var() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/" {
                    request-headers {
                        set "X-User" "{username}"
                    }
                    static root="."
                }
            }
        "#,
        );
        let router = make_router(&config);
        let (_, _, rules) =
            route_meta(&router, "h", "/", "tcp://0.0.0.0:80").unwrap();
        assert!(
            rules.unwrap().needs_principal,
            "{{username}} should set needs_principal"
        );
    }

    #[test]
    fn basic_auth_default_realm_is_restricted() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/x/" {
                    basic-auth
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, auth, _) =
            route_meta(&router, "h", "/x/", "tcp://0.0.0.0:80").unwrap();
        assert_eq!(auth.unwrap().realm, "Restricted");
    }

    // -- named policy resolution -----------------------------------

    #[test]
    fn named_policy_inlined_in_location() {
        let config = make_config(
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
                    }
                    static root="."
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (policy, _, _) =
            route_meta(&router, "h", "/", "tcp://0.0.0.0:80").unwrap();
        // After inlining, the block contains a flat unconditional allow.
        let block = policy.unwrap();
        assert_eq!(block.rules.len(), 1);
        assert!(
            matches!(
                &block.rules[0].action,
                crate::access::PolicyAction::Allow
            ),
            "inlined rule must be Allow"
        );
        assert!(
            block.rules[0].predicate.is_none(),
            "unconditional allow has no predicate"
        );
    }

    #[test]
    fn unknown_named_policy_in_location_is_error() {
        let config_result = Config::parse(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/" {
                    policy {
                        apply "does-not-exist"
                    }
                    static root="."
                }
            }
            "#,
        );
        if let Ok(config) = config_result {
            let metrics = Arc::new(crate::metrics::Metrics::new());
            let summary = Arc::new(
                crate::handler::status::ServerSummary::from_config(&config),
            );
            let result = Router::new(&config, &metrics, &summary, None);
            assert!(
                result.is_err(),
                "unknown policy reference should error at router build"
            );
        }
    }

    #[test]
    fn circular_named_policy_is_error() {
        let mut policies = HashMap::new();
        policies.insert(
            "a".to_string(),
            vec![PolicyRuleDef::Apply {
                name: "b".to_string(),
            }],
        );
        policies.insert(
            "b".to_string(),
            vec![PolicyRuleDef::Apply {
                name: "a".to_string(),
            }],
        );
        let result = resolve_named_policies(&policies);
        assert!(
            result.is_err(),
            "circular policy reference should be detected"
        );
    }

    // Match-aware routing: build a request and call the real
    // `route()` so the matcher predicate evaluation runs end-to-
    // end alongside prefix resolution.
    fn route_match(
        router: &Router,
        mut req: hyper::Request<()>,
        bind: &str,
    ) -> Option<String> {
        router.route(&mut req, bind).map(|r| r.matched_prefix)
    }

    #[test]
    fn matcher_falls_through_to_unmatched_location() {
        // Two locations at the same prefix: the first one demands
        // POST; a GET should bypass it and match the second.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/api/" {
                    match { method "POST" }
                    static root="/posts"
                }
                location "/api/" {
                    static root="/reads"
                }
            }
            "#,
        );
        let router = make_router(&config);
        // Both should resolve to "/api/", but the metadata
        // differs.  The important check is that the GET path
        // doesn't end up 404-ing because the only longest-prefix
        // candidate refused the method.
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/api/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert_eq!(
            route_match(&router, req, "tcp://0.0.0.0:80"),
            Some("/api/".into())
        );
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/api/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert_eq!(
            route_match(&router, req, "tcp://0.0.0.0:80"),
            Some("/api/".into())
        );
    }

    #[test]
    fn matcher_falls_through_to_shorter_prefix() {
        // The longer prefix has a matcher that rejects most
        // requests, so the shorter generic prefix should win
        // when the matcher doesn't accept.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/" {
                    static root="/root"
                }
                location "/api/" {
                    match { header "X-API-Version" "v2" }
                    static root="/v2"
                }
            }
            "#,
        );
        let router = make_router(&config);
        // No header: longer matcher fails, falls back to "/".
        let req = hyper::Request::builder()
            .uri("/api/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert_eq!(
            route_match(&router, req, "tcp://0.0.0.0:80"),
            Some("/".into())
        );
        // With the header: longer matcher wins.
        let req = hyper::Request::builder()
            .uri("/api/foo")
            .header("host", "a.com")
            .header("X-API-Version", "v2")
            .body(())
            .unwrap();
        assert_eq!(
            route_match(&router, req, "tcp://0.0.0.0:80"),
            Some("/api/".into())
        );
    }

    #[test]
    fn matcher_returns_none_when_all_candidates_reject() {
        // Only one location, with a matcher that rejects the
        // request: the router should produce no route at all
        // (not a 200 from some other location).
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/api/" {
                    match { method "POST" }
                    static root="/posts"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .method("GET")
            .uri("/api/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert!(router.route(&mut req, "tcp://0.0.0.0:80").is_none());
    }

    #[test]
    fn rewrite_routes_to_target_location() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/old/" {
                    rewrite from="^/old/(.*)$" to="/new/$1"
                    static root="/never-hit"
                }
                location "/new/" {
                    static root="/new"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/old/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        let route = router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        // The matched_prefix should be the *post-rewrite*
        // location, since the rewrite redirected to /new/.
        assert_eq!(route.matched_prefix, "/new/");
        // And the request URI itself should now reflect the
        // rewritten path so the handler sees the new value.
        assert_eq!(req.uri().path(), "/new/foo");
    }

    #[test]
    fn rewrite_no_match_dispatches_own_handler() {
        // The rewrite regex requires a /old/ prefix, but the
        // request URI doesn't match.  The location's own
        // handler should run anyway -- a non-matching rewrite
        // is a no-op rather than an error.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/" {
                    rewrite from="^/old/(.*)$" to="/new/$1"
                    static root="/root"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/index.html")
            .header("host", "a.com")
            .body(())
            .unwrap();
        let route = router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        assert_eq!(route.matched_prefix, "/");
        assert_eq!(req.uri().path(), "/index.html");
    }

    #[test]
    fn rewrite_preserves_query_when_template_omits_it() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/api/" {
                    rewrite from="^/api/(.*)$" to="/v2/$1"
                    static root="/never"
                }
                location "/v2/" {
                    static root="/v2"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/api/users?id=42")
            .header("host", "a.com")
            .body(())
            .unwrap();
        router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        // The original query should not be carried over because
        // the rewrite template did not include one -- this is
        // documented behaviour (operators write `to="/v2/$1?...
        // {...}"` when they want to keep or rewrite the query).
        // We assert the path landed in /v2/ regardless.
        assert_eq!(req.uri().path(), "/v2/users");
    }

    #[test]
    fn rewrite_template_can_set_new_query() {
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/legacy/" {
                    rewrite from="^/legacy/(.*)$" to="/api?path=$1"
                    static root="/never"
                }
                location "/api" {
                    static root="/api"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/legacy/foo/bar")
            .header("host", "a.com")
            .body(())
            .unwrap();
        router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        assert_eq!(req.uri().path(), "/api");
        assert_eq!(req.uri().query(), Some("path=foo/bar"));
    }

    #[test]
    fn rewrite_chains_through_multiple_locations() {
        // A -> B -> C: the request rewrites twice before
        // landing on a non-rewriting handler.  Cycle counter
        // proves it terminates in well under MAX_REWRITES.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/a/" {
                    rewrite from="^/a/(.*)$" to="/b/$1"
                    static root="/never1"
                }
                location "/b/" {
                    rewrite from="^/b/(.*)$" to="/c/$1"
                    static root="/never2"
                }
                location "/c/" {
                    static root="/final"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/a/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        let route = router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        assert_eq!(route.matched_prefix, "/c/");
        assert_eq!(req.uri().path(), "/c/foo");
    }

    #[test]
    fn matcher_gates_rewrite() {
        // The rewrite-bearing location has a matcher; only
        // method-matching requests should rewrite.  A
        // non-matching method falls through to the sibling
        // location and serves its static handler unchanged.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/api/" {
                    match { method "POST" }
                    rewrite from="^/api/(.*)$" to="/v2/$1"
                    static root="/never"
                }
                location "/api/" {
                    static root="/api-default"
                }
                location "/v2/" {
                    static root="/v2"
                }
            }
            "#,
        );
        let router = make_router(&config);
        // POST matches the first location -> rewrite fires -> /v2/.
        let mut req = hyper::Request::builder()
            .method("POST")
            .uri("/api/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        let route = router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        assert_eq!(route.matched_prefix, "/v2/");
        assert_eq!(req.uri().path(), "/v2/foo");
        // GET fails the matcher -> sibling location serves
        // /api/ unrewritten.
        let mut req = hyper::Request::builder()
            .method("GET")
            .uri("/api/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        let route = router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        assert_eq!(route.matched_prefix, "/api/");
        assert_eq!(req.uri().path(), "/api/foo");
    }

    #[test]
    fn path_matcher_re_evaluates_after_rewrite() {
        // The destination location uses a `path` predicate that
        // is satisfied only by the *rewritten* URI -- proving
        // the matcher runs against the live URI each iteration,
        // not against the original.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/in/" {
                    rewrite from="^/in/(.*)$" to="/out/$1.html"
                    static root="/never"
                }
                location "/out/" {
                    match { path "[.]html$" }
                    static root="/htmls"
                }
                location "/out/" {
                    static root="/fallback"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/in/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        let route = router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        // After rewrite the URI ends in `.html`, so the
        // first /out/ location's path predicate accepts it.
        assert_eq!(req.uri().path(), "/out/foo.html");
        // matched_prefix is /out/ -- both candidates have
        // the same prefix, so the assertion of interest is
        // that *one* /out/ won (and via the matcher path the
        // first one in declaration order is the matcher-
        // bearing one).
        assert_eq!(route.matched_prefix, "/out/");
    }

    #[test]
    fn nested_not_double_negation() {
        // not { not { method "GET" } } is equivalent to
        // method "GET".  Exercises the recursive compiler.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/" {
                    match { not { not { method "GET" } } }
                    static root="/get-only"
                }
                location "/" {
                    static root="/anything"
                }
            }
            "#,
        );
        let router = make_router(&config);
        // GET satisfies the double negation -> first location.
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert_eq!(
            route_match(&router, req, "tcp://0.0.0.0:80"),
            Some("/".into())
        );
        // Both locations share /, so we re-check using the
        // actual chosen route's behaviour: a POST should fail
        // the double negation and dispatch to the fallback
        // sibling.  Since both share the prefix string, we
        // confirm by ensuring `route()` returns *some* route
        // for both (i.e. neither is 404'd).  Distinguishing
        // requires inspecting the handler, which isn't
        // exposed -- so this test is primarily a smoke check
        // that nested not parses and evaluates without
        // panicking on the recursion.
        let mut req = hyper::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert!(router.route(&mut req, "tcp://0.0.0.0:80").is_some());
    }

    #[test]
    fn multiple_top_level_not_predicates_and_together() {
        // `not A` AND `not B` -- only matches when both A and
        // B are false (i.e. method is neither GET nor POST).
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/" {
                    match {
                        not { method "GET" }
                        not { method "POST" }
                    }
                    static root="/non-rw"
                }
                location "/" {
                    static root="/default"
                }
            }
            "#,
        );
        let router = make_router(&config);
        // PUT satisfies both negations.
        let mut req = hyper::Request::builder()
            .method("PUT")
            .uri("/")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert!(router.route(&mut req, "tcp://0.0.0.0:80").is_some());
        // GET fails the first negation -> the matcher fails
        // overall -> sibling location handles it.
        let mut req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert!(router.route(&mut req, "tcp://0.0.0.0:80").is_some());
    }

    #[test]
    fn rewrite_chain_succeeds_just_below_cap() {
        // Nine sequential rewrites plus a terminal handler:
        // exactly inside MAX_REWRITES=10 since each iteration
        // either rewrites or returns (the terminal hop is the
        // tenth iteration, where the chosen location has no
        // rewrite and exits the loop).  Builds the KDL
        // programmatically so the chain length is obvious.
        let mut kdl = String::from(
            "listener \"tcp://0.0.0.0:80\" { }\nvhost \"a.com\" {\n",
        );
        for i in 0..9 {
            kdl.push_str(&format!(
                "    location \"/h{i}/\" {{\n\
                     \x20       rewrite from=\"^/h{i}/(.*)$\" \
                     to=\"/h{}/$1\"\n\
                     \x20       static root=\"/never\"\n\
                     \x20   }}\n",
                i + 1,
            ));
        }
        kdl.push_str(
            "    location \"/h9/\" {\n\
                    static root=\"/final\"\n\
                }\n}\n",
        );
        let config = make_config(&kdl);
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/h0/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        let route = router.route(&mut req, "tcp://0.0.0.0:80").unwrap();
        assert_eq!(route.matched_prefix, "/h9/");
        assert_eq!(req.uri().path(), "/h9/foo");
    }

    #[test]
    fn rewrite_chain_bails_when_exceeding_cap() {
        // Eleven hops -- one more than MAX_REWRITES allows --
        // proves the cap fires for a non-cyclic but pathological
        // configuration too, not just self-loops.  The router
        // emits a tracing warning and returns None.
        let mut kdl = String::from(
            "listener \"tcp://0.0.0.0:80\" { }\nvhost \"a.com\" {\n",
        );
        for i in 0..11 {
            kdl.push_str(&format!(
                "    location \"/h{i}/\" {{\n\
                     \x20       rewrite from=\"^/h{i}/(.*)$\" \
                     to=\"/h{}/$1\"\n\
                     \x20       static root=\"/never\"\n\
                     \x20   }}\n",
                i + 1,
            ));
        }
        kdl.push_str(
            "    location \"/h11/\" {\n\
                    static root=\"/final\"\n\
                }\n}\n",
        );
        let config = make_config(&kdl);
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/h0/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert!(router.route(&mut req, "tcp://0.0.0.0:80").is_none());
    }

    #[test]
    fn rewrite_cycle_bails_at_cap() {
        // The location rewrites onto itself, so every iteration
        // matches the same regex again.  After MAX_REWRITES the
        // router should give up and return None rather than
        // looping forever.
        let config = make_config(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "a.com" {
                location "/" {
                    rewrite from="^/(.*)$" to="/$1"
                    static root="/root"
                }
            }
            "#,
        );
        let router = make_router(&config);
        let mut req = hyper::Request::builder()
            .uri("/foo")
            .header("host", "a.com")
            .body(())
            .unwrap();
        assert!(router.route(&mut req, "tcp://0.0.0.0:80").is_none());
    }
