// Per-location request matchers.
//
// A `Matcher` is a list of `MatchPredicate`s evaluated with AND
// semantics: every predicate must accept the request for the
// matcher to accept.  Within a single predicate (method-set,
// header-value list, query-value list), the listed alternatives
// combine with OR semantics.
//
// Matchers are attached to `location` blocks.  When a location has
// a matcher and the matcher rejects a request, the router falls
// through to the next-best candidate (next-shortest matching
// prefix, in declaration order on ties) instead of dispatching.

use hyper::Method;
use hyper::Request;
use hyper::header::HeaderName;
use regex::Regex;

/// A matcher's predicate list.  AND across the list; OR within
/// each predicate's value set.  An empty `predicates` accepts
/// every request -- callers store `Option<Arc<Matcher>>` so they
/// can avoid building an empty one.
pub struct Matcher {
    pub predicates: Vec<MatchPredicate>,
}

pub enum MatchPredicate {
    /// Request method must be one of the listed methods.
    Method(Vec<Method>),
    /// Named header's value must satisfy one of the listed
    /// `HeaderMatch`es.  A missing header always fails;
    /// `HeaderAbsent` is the explicit form for "match when
    /// missing".
    Header {
        name: HeaderName,
        values: Vec<HeaderMatch>,
    },
    /// Matches precisely when the named header is missing from
    /// the request.  An empty value counts as present, in line
    /// with hyper's HeaderMap.
    HeaderAbsent { name: HeaderName },
    /// Named query parameter must equal one of the listed
    /// values.  The parameter is looked up in the request's
    /// raw query string (first occurrence wins).  Missing
    /// parameter fails the predicate.
    Query {
        name: String,
        values: Vec<String>,
    },
    /// URI path must match at least one of the configured
    /// regexes.  Patterns are evaluated unanchored, so operators
    /// who want a whole-path match should include `^...$`
    /// themselves.
    Path(Vec<Regex>),
    /// Inverts a group of predicates.  The inner list is
    /// AND-evaluated and the whole result negated, so
    /// `not { method "GET"; header "X" "y" }` matches when it
    /// is *not* the case that both inner predicates hold.
    Not(Vec<MatchPredicate>),
}

/// One alternative for a header-value predicate.
pub enum HeaderMatch {
    /// Exact byte-for-byte comparison against the header value.
    Exact(String),
    /// Anchored regex match against the header value.
    Regex(Regex),
}

impl Matcher {
    /// `true` iff every predicate accepts the request.
    pub fn matches<B>(&self, req: &Request<B>) -> bool {
        self.predicates.iter().all(|p| p.matches(req))
    }
}

impl MatchPredicate {
    fn matches<B>(&self, req: &Request<B>) -> bool {
        match self {
            MatchPredicate::Method(methods) => {
                methods.iter().any(|m| m == req.method())
            }
            MatchPredicate::Header { name, values } => {
                match req.headers().get(name) {
                    Some(v) => match v.to_str() {
                        Ok(s) => values.iter().any(|m| match m {
                            HeaderMatch::Exact(want) => want == s,
                            HeaderMatch::Regex(re) => re.is_match(s),
                        }),
                        // Non-UTF-8 header values can't match any
                        // configured pattern -- both string-exact and
                        // regex paths require a `&str`.
                        Err(_) => false,
                    },
                    None => false,
                }
            }
            MatchPredicate::HeaderAbsent { name } => {
                !req.headers().contains_key(name)
            }
            MatchPredicate::Query { name, values } => {
                let q = match req.uri().query() {
                    Some(q) => q,
                    None => return false,
                };
                // First-occurrence semantics keeps behaviour
                // predictable when the same key appears more
                // than once.
                for pair in q.split('&') {
                    let mut it = pair.splitn(2, '=');
                    let k = it.next().unwrap_or("");
                    let v = it.next().unwrap_or("");
                    if k == name {
                        return values.iter().any(|w| w == v);
                    }
                }
                false
            }
            MatchPredicate::Path(patterns) => {
                let path = req.uri().path();
                patterns.iter().any(|re| re.is_match(path))
            }
            MatchPredicate::Not(inner) => {
                // AND inside, then invert.  An empty inner list
                // shouldn't reach runtime (the parser rejects it)
                // but if it does, treat it as a vacuous truth
                // that the negation flips to `false`.
                let inner_all = inner.iter().all(|p| p.matches(req));
                !inner_all
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    fn req(method: &str, uri: &str, headers: &[(&str, &str)])
        -> Request<()>
    {
        let mut b = Request::builder()
            .method(method)
            .uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap()
    }

    #[test]
    fn method_predicate_or_within_list() {
        let m = Matcher {
            predicates: vec![MatchPredicate::Method(vec![
                Method::POST,
                Method::PUT,
            ])],
        };
        assert!(m.matches(&req("POST", "/", &[])));
        assert!(m.matches(&req("PUT", "/", &[])));
        assert!(!m.matches(&req("GET", "/", &[])));
    }

    #[test]
    fn header_predicate_exact_and_regex() {
        let m = Matcher {
            predicates: vec![MatchPredicate::Header {
                name: HeaderName::from_static("x-api-version"),
                values: vec![
                    HeaderMatch::Exact("v1".to_string()),
                    HeaderMatch::Regex(
                        Regex::new("^v[23]$").unwrap()
                    ),
                ],
            }],
        };
        assert!(m.matches(
            &req("GET", "/", &[("X-API-Version", "v1")])
        ));
        assert!(m.matches(
            &req("GET", "/", &[("X-API-Version", "v2")])
        ));
        assert!(m.matches(
            &req("GET", "/", &[("X-API-Version", "v3")])
        ));
        assert!(!m.matches(
            &req("GET", "/", &[("X-API-Version", "v4")])
        ));
        // Missing header -> no match.
        assert!(!m.matches(&req("GET", "/", &[])));
    }

    #[test]
    fn query_predicate_first_occurrence_wins() {
        let m = Matcher {
            predicates: vec![MatchPredicate::Query {
                name: "format".to_string(),
                values: vec!["json".to_string()],
            }],
        };
        assert!(m.matches(&req("GET", "/?format=json", &[])));
        assert!(m.matches(&req("GET", "/?a=1&format=json", &[])));
        assert!(!m.matches(&req("GET", "/?format=xml", &[])));
        // First-occurrence: a later `format=json` does not save
        // an earlier `format=xml`.
        assert!(!m.matches(
            &req("GET", "/?format=xml&format=json", &[])
        ));
        // Missing query string entirely.
        assert!(!m.matches(&req("GET", "/", &[])));
    }

    #[test]
    fn predicates_combine_with_and() {
        let m = Matcher {
            predicates: vec![
                MatchPredicate::Method(vec![Method::POST]),
                MatchPredicate::Header {
                    name: HeaderName::from_static("x-tenant"),
                    values: vec![HeaderMatch::Exact(
                        "acme".to_string()
                    )],
                },
            ],
        };
        assert!(m.matches(
            &req("POST", "/", &[("X-Tenant", "acme")])
        ));
        // Method fails.
        assert!(!m.matches(
            &req("GET", "/", &[("X-Tenant", "acme")])
        ));
        // Header fails.
        assert!(!m.matches(
            &req("POST", "/", &[("X-Tenant", "other")])
        ));
    }

    #[test]
    fn empty_predicate_list_accepts() {
        // Defensive: the config parser refuses to build an empty
        // matcher, but the evaluator must still degrade safely if
        // one slips through (e.g. via a programmatic builder).
        let m = Matcher { predicates: vec![] };
        assert!(m.matches(&req("GET", "/", &[])));
    }

    #[test]
    fn header_absent_predicate() {
        let m = Matcher {
            predicates: vec![MatchPredicate::HeaderAbsent {
                name: HeaderName::from_static("authorization"),
            }],
        };
        assert!(m.matches(&req("GET", "/", &[])));
        // Even an empty header counts as present (hyper
        // distinguishes the two), so the predicate fails.
        assert!(!m.matches(
            &req("GET", "/", &[("Authorization", "")])
        ));
        assert!(!m.matches(
            &req("GET", "/", &[("Authorization", "Bearer x")])
        ));
    }

    #[test]
    fn path_predicate_is_unanchored() {
        // Patterns are matched unanchored, so a bare `admin`
        // matches anywhere in the path -- including the
        // middle of a segment.  This is documented behaviour;
        // operators who want strict boundaries write
        // explicit `^...$` or use word boundaries.
        let m = Matcher {
            predicates: vec![MatchPredicate::Path(vec![
                Regex::new("admin").unwrap(),
            ])],
        };
        assert!(m.matches(&req("GET", "/admin/users", &[])));
        assert!(m.matches(&req("GET", "/api/admin", &[])));
        assert!(m.matches(&req("GET", "/uber/admin/x", &[])));
        // Substring match: even `/sysadmin/x` hits because
        // the regex isn't anchored.
        assert!(m.matches(&req("GET", "/sysadmin/x", &[])));
        assert!(!m.matches(&req("GET", "/users", &[])));
    }

    #[test]
    fn path_predicate_anchors_when_caret_dollar() {
        // Operators control anchoring themselves.  `^/admin$`
        // matches only the exact path.
        let m = Matcher {
            predicates: vec![MatchPredicate::Path(vec![
                Regex::new("^/admin$").unwrap(),
            ])],
        };
        assert!(m.matches(&req("GET", "/admin", &[])));
        assert!(!m.matches(&req("GET", "/admin/users", &[])));
        assert!(!m.matches(&req("GET", "/sysadmin", &[])));
    }

    #[test]
    fn path_predicate_or_within_list() {
        let m = Matcher {
            predicates: vec![MatchPredicate::Path(vec![
                Regex::new(r"\.jpg$").unwrap(),
                Regex::new(r"\.png$").unwrap(),
            ])],
        };
        assert!(m.matches(&req("GET", "/img/cat.jpg", &[])));
        assert!(m.matches(&req("GET", "/img/cat.png", &[])));
        assert!(!m.matches(&req("GET", "/img/cat.gif", &[])));
    }

    #[test]
    fn not_predicate_inverts_and_of_inner() {
        // not { method GET } -> matches anything except GET.
        let m = Matcher {
            predicates: vec![MatchPredicate::Not(vec![
                MatchPredicate::Method(vec![Method::GET]),
            ])],
        };
        assert!(m.matches(&req("POST", "/", &[])));
        assert!(!m.matches(&req("GET", "/", &[])));
    }

    #[test]
    fn not_predicate_and_of_multiple_inner() {
        // not { method GET; header X y } -> matches unless both
        // (method is GET AND X=y); so a GET with X=other still
        // matches because the inner AND is false.
        let m = Matcher {
            predicates: vec![MatchPredicate::Not(vec![
                MatchPredicate::Method(vec![Method::GET]),
                MatchPredicate::Header {
                    name: HeaderName::from_static("x-blocked"),
                    values: vec![HeaderMatch::Exact(
                        "yes".to_string()
                    )],
                },
            ])],
        };
        // Both inner predicates true -> outer negation fails.
        assert!(!m.matches(
            &req("GET", "/", &[("X-Blocked", "yes")])
        ));
        // Method matches but header doesn't -> inner AND false
        // -> negation matches.
        assert!(m.matches(
            &req("GET", "/", &[("X-Blocked", "no")])
        ));
        // Neither matches -> negation matches.
        assert!(m.matches(&req("POST", "/", &[])));
    }

    #[test]
    fn non_utf8_header_value_never_matches() {
        let mut r: Request<()> = Request::builder()
            .method("GET")
            .uri("/")
            .body(())
            .unwrap();
        r.headers_mut().insert(
            HeaderName::from_static("x-bin"),
            hyper::header::HeaderValue::from_bytes(b"\xff\xfe")
                .unwrap(),
        );
        let m = Matcher {
            predicates: vec![MatchPredicate::Header {
                name: HeaderName::from_static("x-bin"),
                values: vec![HeaderMatch::Regex(
                    Regex::new(".*").unwrap()
                )],
            }],
        };
        assert!(!m.matches(&r));
    }
}
