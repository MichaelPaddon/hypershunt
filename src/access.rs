// Policy-based access control.
//
// A PolicyBlock is a flat list of rules evaluated in declaration order.
// The first matching rule wins.  Rules may have a Predicate (which may
// require authentication) or no predicate (unconditional).
//
// apply is resolved to a flat inline at config time; there are no
// sub-block references at evaluation time.
//
// Predicate evaluation is strictly sequential.  Auth predicates
// (Authenticated, User, Group) return Challenge(401) when the request
// is anonymous, causing an immediate 401 response.  Not wraps an inner
// predicate and converts Challenge to Match (anonymous users satisfy
// "not authenticated").

use crate::auth::Principal;
use async_trait::async_trait;
use ipnet::IpNet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

// -- Auth provider ------------------------------------------------

/// Provides authenticated identity on demand inside the evaluator.
/// Called at most once per request (result is cached in EvalContext).
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self) -> Principal;
}

/// Always returns `Principal::Anonymous`.  Used for TCP proxy contexts
/// where HTTP authentication is not available.
pub struct AnonymousAuthProvider;

#[async_trait]
impl AuthProvider for AnonymousAuthProvider {
    async fn authenticate(&self) -> Principal {
        Principal::Anonymous
    }
}

// -- Predicate tree -----------------------------------------------

/// A predicate tests properties of the incoming request.
///
/// Multiple values on a single leaf (Address, Country, User, Group)
/// are OR-combined.  And combines its children with AND semantics,
/// evaluated left-to-right with short-circuit.  Not negates its inner
/// predicate; it converts Challenge to Match (anonymous satisfies
/// "not authenticated").
#[derive(Clone, Debug)]
pub enum Predicate {
    /// Client address matches any of the listed CIDRs/IPs.
    Address(Vec<IpNet>),
    /// ISO 3166-1 alpha-2 country code matches any of the listed codes.
    Country(Vec<String>),
    /// Authenticated username matches any of the listed names.
    User(Vec<String>),
    /// Authenticated user is a member of any of the listed groups.
    Group(Vec<String>),
    /// Request is authenticated (any user).
    Authenticated,
    /// The inner predicate does not match.  Challenge becomes Match.
    Not(Box<Predicate>),
    /// All inner predicates match (evaluated left-to-right).
    And(Vec<Predicate>),
}

impl Predicate {
    /// True iff any leaf in the tree is a Country predicate.
    pub fn needs_geoip(&self) -> bool {
        match self {
            Self::Country(_) => true,
            Self::Not(inner) => inner.needs_geoip(),
            Self::And(preds) => preds.iter().any(|p| p.needs_geoip()),
            _ => false,
        }
    }

    /// True iff any leaf in the tree requires authentication.
    pub fn needs_auth(&self) -> bool {
        match self {
            Self::Authenticated | Self::User(_) | Self::Group(_) => true,
            Self::Not(inner) => inner.needs_auth(),
            Self::And(preds) => preds.iter().any(|p| p.needs_auth()),
            _ => false,
        }
    }
}

// -- Result of predicate evaluation --------------------------------

enum PredicateResult {
    Match,
    NoMatch,
    /// Anonymous user encountered an auth predicate; issue a challenge.
    Challenge(u16),
}

// -- Policy action and rule ----------------------------------------

#[derive(Clone, Debug)]
pub enum PolicyAction {
    Allow,
    Deny { code: u16 },
    Redirect { to: String, code: u16 },
}

/// A single rule: an optional predicate (None = unconditional) and an
/// action to take when the predicate matches.
#[derive(Clone, Debug)]
pub struct PolicyRule {
    pub predicate: Option<Predicate>,
    pub action: PolicyAction,
}

// -- Policy block --------------------------------------------------

/// A flat list of rules.  apply references are inlined at config time
/// so there are no sub-blocks at evaluation time.
#[derive(Clone, Debug)]
pub struct PolicyBlock {
    pub rules: Vec<PolicyRule>,
    /// True iff any predicate in any rule uses Country.
    pub needs_geoip: bool,
}

impl PolicyBlock {
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        let needs_geoip = rules
            .iter()
            .any(|r| r.predicate.as_ref().is_some_and(|p| p.needs_geoip()));
        PolicyBlock { rules, needs_geoip }
    }

    /// Evaluate the policy against the request context.  The first rule
    /// whose predicate matches fires its action.  If a Challenge is
    /// signalled by an auth predicate, a 401 is returned immediately.
    /// If no rule matches, the default is Deny(403).
    pub async fn evaluate(&self, ctx: &mut EvalContext<'_>) -> PolicyOutcome {
        for rule in &self.rules {
            let result = match &rule.predicate {
                None => PredicateResult::Match,
                Some(pred) => eval_predicate(pred, ctx).await,
            };
            match result {
                PredicateResult::Match => {
                    return match &rule.action {
                        PolicyAction::Allow => PolicyOutcome::Allow,
                        PolicyAction::Deny { code } => {
                            PolicyOutcome::Deny(*code)
                        }
                        PolicyAction::Redirect { to, code } => {
                            PolicyOutcome::Redirect(to.clone(), *code)
                        }
                    };
                }
                PredicateResult::Challenge(code) => {
                    return PolicyOutcome::Deny(code);
                }
                PredicateResult::NoMatch => continue,
            }
        }
        PolicyOutcome::Deny(403)
    }
}

// -- Public outcome ------------------------------------------------

#[derive(Debug)]
pub enum PolicyOutcome {
    Allow,
    Deny(u16),
    Redirect(String, u16),
}

// -- Evaluation context --------------------------------------------

pub struct EvalContext<'a> {
    pub peer: IpAddr,
    pub country: Option<&'a str>,
    // None until the first identity predicate is evaluated.
    principal: Option<Principal>,
    auth: &'a dyn AuthProvider,
}

impl<'a> EvalContext<'a> {
    pub fn new(
        peer: IpAddr,
        country: Option<&'a str>,
        auth: &'a dyn AuthProvider,
    ) -> Self {
        EvalContext {
            peer: normalise(peer),
            country,
            principal: None,
            auth,
        }
    }

    /// Consume the context and return the principal resolved during
    /// evaluation (if any), for use in header substitution.
    pub fn take_principal(self) -> Principal {
        self.principal.unwrap_or(Principal::Anonymous)
    }
}

// -- Internal evaluation -------------------------------------------

// Box the future so recursive Not/And chains compile without a fixed
// stack frame size.
fn eval_predicate<'a>(
    pred: &'a Predicate,
    ctx: &'a mut EvalContext<'_>,
) -> Pin<Box<dyn Future<Output = PredicateResult> + Send + 'a>> {
    Box::pin(async move {
        match pred {
            Predicate::Address(nets) => {
                if nets.iter().any(|n| n.contains(&ctx.peer)) {
                    PredicateResult::Match
                } else {
                    PredicateResult::NoMatch
                }
            }

            Predicate::Country(codes) => {
                if ctx.country.is_some_and(|c| {
                    codes.iter().any(|code| c == code.as_str())
                }) {
                    PredicateResult::Match
                } else {
                    PredicateResult::NoMatch
                }
            }

            Predicate::Authenticated => match resolve_principal(ctx).await {
                Principal::Authenticated(_) => PredicateResult::Match,
                Principal::Anonymous => PredicateResult::Challenge(401),
            },

            Predicate::User(names) => match resolve_principal(ctx).await {
                Principal::Authenticated(id)
                    if names.contains(&id.username) =>
                {
                    PredicateResult::Match
                }
                Principal::Authenticated(_) => PredicateResult::NoMatch,
                Principal::Anonymous => PredicateResult::Challenge(401),
            },

            Predicate::Group(groups) => match resolve_principal(ctx).await {
                Principal::Authenticated(id)
                    if id.groups.iter().any(|g| groups.contains(g)) =>
                {
                    PredicateResult::Match
                }
                Principal::Authenticated(_) => PredicateResult::NoMatch,
                Principal::Anonymous => PredicateResult::Challenge(401),
            },

            // Challenge becomes Match: anonymous users satisfy
            // "not authenticated"; no 401 is issued.
            Predicate::Not(inner) => match eval_predicate(inner, ctx).await {
                PredicateResult::Match => PredicateResult::NoMatch,
                PredicateResult::NoMatch | PredicateResult::Challenge(_) => {
                    PredicateResult::Match
                }
            },

            // Evaluated left-to-right with short-circuit: the first
            // NoMatch or Challenge stops the chain immediately.
            Predicate::And(preds) => {
                for p in preds {
                    match eval_predicate(p, ctx).await {
                        PredicateResult::Match => continue,
                        other => return other,
                    }
                }
                PredicateResult::Match
            }
        }
    })
}

// Lazy-load and cache the authenticated principal.  Called at most
// once per request across all predicate evaluations.
async fn resolve_principal<'a>(ctx: &'a mut EvalContext<'_>) -> &'a Principal {
    if ctx.principal.is_none() {
        ctx.principal = Some(ctx.auth.authenticate().await);
    }
    ctx.principal.as_ref().unwrap()
}

// Normalise IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to plain IPv4
// so that `address "10.0.0.0/8"` matches whether the peer is reported
// as 10.1.2.3 or ::ffff:10.1.2.3.
fn normalise(addr: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = addr
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(v4);
    }
    addr
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Identity;
    use std::net::Ipv6Addr;
    use std::sync::{Arc, Mutex};

    // -- Mock auth provider ----------------------------------------

    struct MockAuth {
        identity: Option<(String, Vec<String>)>,
        calls: Mutex<usize>,
    }

    impl MockAuth {
        fn anon() -> Self {
            MockAuth {
                identity: None,
                calls: Mutex::new(0),
            }
        }

        fn authed(username: &str, groups: &[&str]) -> Self {
            MockAuth {
                identity: Some((
                    username.to_owned(),
                    groups.iter().map(|s| s.to_string()).collect(),
                )),
                calls: Mutex::new(0),
            }
        }

        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl AuthProvider for MockAuth {
        async fn authenticate(&self) -> Principal {
            *self.calls.lock().unwrap() += 1;
            match &self.identity {
                None => Principal::Anonymous,
                Some((username, groups)) => {
                    Principal::Authenticated(Identity {
                        username: username.clone(),
                        groups: groups.clone(),
                    })
                }
            }
        }
    }

    // -- Test helpers ----------------------------------------------

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ctx<'a>(
        peer: &str,
        country: Option<&'a str>,
        auth: &'a dyn AuthProvider,
    ) -> EvalContext<'a> {
        EvalContext::new(ip(peer), country, auth)
    }

    fn block(rules: Vec<PolicyRule>) -> Arc<PolicyBlock> {
        Arc::new(PolicyBlock::new(rules))
    }

    fn rule(pred: Option<Predicate>, action: PolicyAction) -> PolicyRule {
        PolicyRule {
            predicate: pred,
            action,
        }
    }

    fn allow(pred: Option<Predicate>) -> PolicyRule {
        rule(pred, PolicyAction::Allow)
    }

    fn deny(code: u16, pred: Option<Predicate>) -> PolicyRule {
        rule(pred, PolicyAction::Deny { code })
    }

    // -- Basic terminal actions ------------------------------------

    #[tokio::test]
    async fn allow_unconditional() {
        let b = block(vec![allow(None)]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    #[tokio::test]
    async fn deny_unconditional() {
        let b = block(vec![deny(403, None)]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    #[tokio::test]
    async fn redirect_unconditional() {
        let b = block(vec![rule(
            None,
            PolicyAction::Redirect {
                to: "/login".into(),
                code: 302,
            },
        )]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        match b.evaluate(&mut c).await {
            PolicyOutcome::Redirect(to, code) => {
                assert_eq!(to, "/login");
                assert_eq!(code, 302);
            }
            _ => panic!("expected redirect"),
        }
    }

    #[tokio::test]
    async fn no_match_defaults_to_deny_403() {
        let b = block(vec![]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    // -- First-match ordering --------------------------------------

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let b = block(vec![
            deny(403, Some(Predicate::Address(vec![net("10.0.0.0/8")]))),
            // Second rule also matches but must not be reached.
            allow(Some(Predicate::Address(vec![net("10.0.0.0/8")]))),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("10.0.0.1", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    // -- Address predicate -----------------------------------------

    #[tokio::test]
    async fn address_single_cidr_match() {
        let b = block(vec![
            allow(Some(Predicate::Address(vec![net("10.0.0.0/8")]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("10.1.2.3", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    #[tokio::test]
    async fn address_no_match_falls_through() {
        let b = block(vec![
            allow(Some(Predicate::Address(vec![net("10.0.0.0/8")]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    #[tokio::test]
    async fn address_multi_cidr_or() {
        let b = block(vec![
            allow(Some(Predicate::Address(vec![
                net("10.0.0.0/8"),
                net("192.168.0.0/16"),
            ]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        for peer in ["10.0.0.1", "192.168.1.1"] {
            let mut c = ctx(peer, None, &a);
            assert!(
                matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow),
                "{peer} should match"
            );
        }
        let mut c = ctx("8.8.8.8", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    #[tokio::test]
    async fn ipv4_mapped_v6_matches_v4_rule() {
        let b = block(vec![
            allow(Some(Predicate::Address(vec![net("10.0.0.0/8")]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        let mapped: IpAddr =
            "::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap().into();
        let mut c = EvalContext::new(mapped, None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    // -- Country predicate -----------------------------------------

    #[tokio::test]
    async fn country_single_match() {
        let b = block(vec![
            allow(Some(Predicate::Country(vec!["US".into()]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", Some("US"), &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    #[tokio::test]
    async fn country_multi_or() {
        let b = block(vec![
            allow(Some(Predicate::Country(vec![
                "US".into(),
                "CA".into(),
                "GB".into(),
            ]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        for cc in ["US", "CA", "GB"] {
            let mut c = ctx("1.2.3.4", Some(cc), &a);
            assert!(
                matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow),
                "{cc} should match"
            );
        }
        let mut c = ctx("1.2.3.4", Some("DE"), &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    #[tokio::test]
    async fn country_none_never_satisfies() {
        let b = block(vec![
            allow(Some(Predicate::Country(vec!["US".into()]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("127.0.0.1", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    // -- Authenticated predicate -----------------------------------

    #[tokio::test]
    async fn authenticated_authed_matches() {
        let b =
            block(vec![allow(Some(Predicate::Authenticated)), deny(403, None)]);
        let a = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    #[tokio::test]
    async fn authenticated_anon_challenges() {
        // Anonymous user triggers Challenge(401) → Deny(401).
        let b =
            block(vec![allow(Some(Predicate::Authenticated)), deny(403, None)]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(401)));
    }

    // -- User predicate --------------------------------------------

    #[tokio::test]
    async fn user_correct_matches() {
        let b = block(vec![
            allow(Some(Predicate::User(vec!["alice".into()]))),
            deny(403, None),
        ]);
        let a = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    #[tokio::test]
    async fn user_wrong_user_no_match() {
        // Authenticated but wrong name → NoMatch (not Challenge).
        let b = block(vec![
            allow(Some(Predicate::User(vec!["alice".into()]))),
            deny(403, None),
        ]);
        let a = MockAuth::authed("bob", &[]);
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    #[tokio::test]
    async fn user_anon_challenges() {
        let b = block(vec![allow(Some(Predicate::User(vec!["alice".into()])))]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(401)));
    }

    #[tokio::test]
    async fn user_multi_or() {
        let b = block(vec![
            allow(Some(Predicate::User(vec!["alice".into(), "bob".into()]))),
            deny(403, None),
        ]);
        let alice = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &alice);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));

        let bob = MockAuth::authed("bob", &[]);
        let mut c2 = ctx("1.2.3.4", None, &bob);
        assert!(matches!(b.evaluate(&mut c2).await, PolicyOutcome::Allow));

        let charlie = MockAuth::authed("charlie", &[]);
        let mut c3 = ctx("1.2.3.4", None, &charlie);
        assert!(matches!(
            b.evaluate(&mut c3).await,
            PolicyOutcome::Deny(403)
        ));
    }

    // -- Group predicate -------------------------------------------

    #[tokio::test]
    async fn group_member_matches() {
        let b = block(vec![
            allow(Some(Predicate::Group(vec!["admin".into()]))),
            deny(403, None),
        ]);
        let a = MockAuth::authed("alice", &["admin"]);
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    #[tokio::test]
    async fn group_non_member_no_match() {
        let b = block(vec![
            allow(Some(Predicate::Group(vec!["admin".into()]))),
            deny(403, None),
        ]);
        let a = MockAuth::authed("bob", &["users"]);
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    #[tokio::test]
    async fn group_anon_challenges() {
        let b =
            block(vec![allow(Some(Predicate::Group(vec!["admin".into()])))]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(401)));
    }

    #[tokio::test]
    async fn group_multi_or() {
        let b = block(vec![
            allow(Some(Predicate::Group(vec!["admin".into(), "ops".into()]))),
            deny(403, None),
        ]);
        let admin = MockAuth::authed("alice", &["admin"]);
        let mut c1 = ctx("1.2.3.4", None, &admin);
        assert!(matches!(b.evaluate(&mut c1).await, PolicyOutcome::Allow));

        let ops = MockAuth::authed("bob", &["ops"]);
        let mut c2 = ctx("1.2.3.4", None, &ops);
        assert!(matches!(b.evaluate(&mut c2).await, PolicyOutcome::Allow));

        let user = MockAuth::authed("charlie", &["users"]);
        let mut c3 = ctx("1.2.3.4", None, &user);
        assert!(matches!(
            b.evaluate(&mut c3).await,
            PolicyOutcome::Deny(403)
        ));
    }

    // -- Not predicate ---------------------------------------------

    #[tokio::test]
    async fn not_address_negates() {
        // In-range → NoMatch; out-of-range → Match.
        let b = block(vec![
            allow(Some(Predicate::Not(Box::new(Predicate::Address(vec![
                net("10.0.0.0/8"),
            ]))))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        let mut in_range = ctx("10.0.0.1", None, &a);
        assert!(matches!(
            b.evaluate(&mut in_range).await,
            PolicyOutcome::Deny(403)
        ));
        let mut out_range = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            b.evaluate(&mut out_range).await,
            PolicyOutcome::Allow
        ));
    }

    #[tokio::test]
    async fn not_authenticated_anon_matches_no_challenge() {
        // Anonymous satisfies "not authenticated" → no 401 issued.
        let b = block(vec![
            deny(
                403,
                Some(Predicate::Not(Box::new(Predicate::Authenticated))),
            ),
            allow(None),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Deny(403)));
    }

    #[tokio::test]
    async fn not_authenticated_authed_no_match() {
        // Authenticated user does NOT satisfy "not authenticated".
        let b = block(vec![
            deny(
                403,
                Some(Predicate::Not(Box::new(Predicate::Authenticated))),
            ),
            allow(None),
        ]);
        let a = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, PolicyOutcome::Allow));
    }

    #[tokio::test]
    async fn not_challenge_becomes_match() {
        // Challenge from inner auth predicate is suppressed by Not.
        // Evaluating "not authenticated" for anon → Match (deny fires).
        let pred = Predicate::Not(Box::new(Predicate::Authenticated));
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        let result = eval_predicate(&pred, &mut c).await;
        assert!(
            matches!(result, PredicateResult::Match),
            "Not(Authenticated) for anon must be Match"
        );
    }

    // -- And predicate: sequential evaluation ----------------------

    #[tokio::test]
    async fn and_address_then_auth_address_fails_auth_skipped() {
        // address check fails → And short-circuits; auth never called.
        let pred = Predicate::And(vec![
            Predicate::Address(vec![net("10.0.0.0/8")]),
            Predicate::Authenticated,
        ]);
        let a = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &a);
        let result = eval_predicate(&pred, &mut c).await;
        assert!(matches!(result, PredicateResult::NoMatch));
        assert_eq!(a.call_count(), 0, "auth must not be called");
    }

    #[tokio::test]
    async fn and_auth_then_address_auth_evaluated_first() {
        // Declares auth before address: auth is evaluated first.
        // This is the key regression test for the evaluation-order bug.
        let pred = Predicate::And(vec![
            Predicate::Authenticated,                    // first
            Predicate::Address(vec![net("10.0.0.0/8")]), // second
        ]);
        // Anonymous → Authenticated Challenge fires before address.
        let a = MockAuth::anon();
        let mut c = ctx("10.0.0.1", None, &a); // address would match
        let result = eval_predicate(&pred, &mut c).await;
        assert!(
            matches!(result, PredicateResult::Challenge(401)),
            "auth predicate must be evaluated first (Challenge expected)"
        );
    }

    #[tokio::test]
    async fn and_all_match() {
        let pred = Predicate::And(vec![
            Predicate::Address(vec![net("10.0.0.0/8")]),
            Predicate::Authenticated,
        ]);
        let a = MockAuth::authed("alice", &[]);
        let mut c = ctx("10.0.0.1", None, &a);
        let result = eval_predicate(&pred, &mut c).await;
        assert!(matches!(result, PredicateResult::Match));
    }

    #[tokio::test]
    async fn and_challenge_short_circuits() {
        // Auth challenge stops the chain; subsequent predicates not evaluated.
        let pred = Predicate::And(vec![
            Predicate::Authenticated,
            Predicate::Address(vec![net("10.0.0.0/8")]),
        ]);
        let a = MockAuth::anon();
        // Use an address that would NOT match, to confirm address is skipped.
        let mut c = ctx("1.2.3.4", None, &a);
        let result = eval_predicate(&pred, &mut c).await;
        assert!(matches!(result, PredicateResult::Challenge(401)));
    }

    // -- Lazy auth: called at most once ----------------------------

    #[tokio::test]
    async fn auth_called_at_most_once_across_multiple_predicates() {
        let pred = Predicate::And(vec![
            Predicate::Authenticated,
            Predicate::Group(vec!["admin".into()]),
        ]);
        let a = MockAuth::authed("alice", &["admin"]);
        let mut c = ctx("1.2.3.4", None, &a);
        eval_predicate(&pred, &mut c).await;
        assert_eq!(a.call_count(), 1, "auth must be called exactly once");
    }

    #[tokio::test]
    async fn auth_not_called_for_address_only_block() {
        let b = block(vec![
            allow(Some(Predicate::Address(vec![net("10.0.0.0/8")]))),
            deny(403, None),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("10.0.0.1", None, &a);
        b.evaluate(&mut c).await;
        assert_eq!(a.call_count(), 0, "auth must not be called");
    }

    // -- needs_geoip / needs_auth flags ----------------------------

    #[tokio::test]
    async fn needs_geoip_from_country_leaf() {
        let p = Predicate::Country(vec!["US".into()]);
        assert!(p.needs_geoip());
    }

    #[tokio::test]
    async fn needs_geoip_from_country_inside_and() {
        let p = Predicate::And(vec![
            Predicate::Address(vec![net("10.0.0.0/8")]),
            Predicate::Country(vec!["US".into()]),
        ]);
        assert!(p.needs_geoip());
    }

    #[tokio::test]
    async fn needs_geoip_from_country_inside_not() {
        let p = Predicate::Not(Box::new(Predicate::Country(vec!["CN".into()])));
        assert!(p.needs_geoip());
    }

    #[tokio::test]
    async fn needs_geoip_false_for_address_only() {
        let p = Predicate::Address(vec![net("10.0.0.0/8")]);
        assert!(!p.needs_geoip());
    }

    #[tokio::test]
    async fn needs_auth_from_authenticated() {
        assert!(Predicate::Authenticated.needs_auth());
    }

    #[tokio::test]
    async fn needs_auth_from_user() {
        assert!(Predicate::User(vec!["alice".into()]).needs_auth());
    }

    #[tokio::test]
    async fn needs_auth_from_group() {
        assert!(Predicate::Group(vec!["admin".into()]).needs_auth());
    }

    #[tokio::test]
    async fn needs_auth_from_not_authenticated() {
        let p = Predicate::Not(Box::new(Predicate::Authenticated));
        assert!(p.needs_auth());
    }

    #[tokio::test]
    async fn needs_auth_false_for_address() {
        assert!(!Predicate::Address(vec![net("10.0.0.0/8")]).needs_auth());
    }

    #[tokio::test]
    async fn block_needs_geoip_flag_from_rules() {
        let b = PolicyBlock::new(vec![
            allow(Some(Predicate::Country(vec!["US".into()]))),
            allow(Some(Predicate::Group(vec!["admin".into()]))),
        ]);
        assert!(b.needs_geoip, "country rule must set needs_geoip");
    }
}
