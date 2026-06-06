// Listener-set diffing for hot reload.
//
// `diff_listeners` compares two `Vec<ListenerConfig>` (the running set
// vs the freshly-parsed new set) by `ListenerKey` (the bind string)
// and bucketises each one into added / removed / unchanged.  The
// reload orchestrator uses those buckets to decide what to bind, what
// to drain, and what to leave alone.

use crate::config::ListenerConfig;
use std::collections::HashMap;

/// Identity of a listener for the purposes of reload diffing.
///
/// Two listeners with the same `ListenerKey` refer to the same kernel
/// socket and can therefore be "carried over" across a reload without
/// rebinding.  Listener-level fields that *aren't* part of the key
/// (timeouts, max_connections, TLS cert paths, ...) may still differ
/// between old and new; those changes don't take effect in v1 -- the
/// existing listener task keeps the captured values until a full
/// restart.  Routing, vhost, and handler config flows through the
/// swapped `AppState` so it does take effect on the same listener.
pub type ListenerKey = String;

/// Canonical key for diffing.  We use the URL form of the bind
/// (`tcp://...`, `udp://...`, `unix-stream:/...`, etc.), which
/// uniquely identifies both the socket family and the address.
pub fn listener_key(cfg: &ListenerConfig) -> ListenerKey {
    cfg.bind.to_url()
}

/// Result of comparing the running listener set against a freshly
/// parsed config.  All three vectors carry references back into the
/// caller's old/new slices; the reload orchestrator uses these to
/// decide what to bind, what to drain, and what to leave alone.
#[derive(Debug)]
pub struct ListenerDiff<'a> {
    /// Bind strings present in the new config but not the old.  The
    /// reload path tries to bind these in-process.  Any failure
    /// (privileges, port-in-use, ...) aborts the entire reload so
    /// the old config keeps serving unchanged.
    pub added: Vec<&'a ListenerConfig>,
    /// Bind strings present in the old config but not the new.  The
    /// reload path flips each one's stop_accept channel so the
    /// listener task drains its in-flight connections and exits.
    pub removed: Vec<&'a ListenerConfig>,
    /// Bind strings present in both.  Paired (old, new) so callers
    /// can detect field-level changes and (in a future tightening)
    /// reject or warn about edits that don't take effect today.
    /// Computed and asserted on by the diff tests; the orchestrator
    /// doesn't consume it yet, hence dead in non-test builds.
    #[cfg_attr(not(test), allow(dead_code))]
    pub unchanged: Vec<(&'a ListenerConfig, &'a ListenerConfig)>,
}

/// Compare two listener sets by `ListenerKey` and bucket each into
/// added / removed / unchanged.
pub fn diff_listeners<'a>(
    old: &'a [ListenerConfig],
    new: &'a [ListenerConfig],
) -> ListenerDiff<'a> {
    // Build lookup tables keyed by ListenerKey so the diff is O(N+M)
    // regardless of declaration order in either config file.
    let old_by_key: HashMap<ListenerKey, &ListenerConfig> =
        old.iter().map(|c| (listener_key(c), c)).collect();
    let new_by_key: HashMap<ListenerKey, &ListenerConfig> =
        new.iter().map(|c| (listener_key(c), c)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = Vec::new();

    for (key, new_cfg) in &new_by_key {
        match old_by_key.get(key) {
            Some(old_cfg) => unchanged.push((*old_cfg, *new_cfg)),
            None => added.push(*new_cfg),
        }
    }
    for (key, old_cfg) in &old_by_key {
        if !new_by_key.contains_key(key) {
            removed.push(*old_cfg);
        }
    }
    // Stable ordering for deterministic test assertions and log output.
    added.sort_by_key(|c| listener_key(c));
    removed.sort_by_key(|c| listener_key(c));
    unchanged.sort_by_key(|(o, _)| listener_key(o));

    ListenerDiff { added, removed, unchanged }
}
