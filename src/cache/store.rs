// The single process-wide response store: an LRU map of cache key ->
// stored response, bounded by a total byte budget.  Insertion evicts
// least-recently-used entries until the store fits the budget; a
// background task sweeps stale (past-freshness) entries on a timer and
// refreshes the live gauges.
//
// `lru::LruCache` provides the recency ordering; byte accounting and
// the budget live here because `LruCache` itself is count-bounded.
// Access goes through a `Mutex` (matching `rate_limit.rs`): the
// critical section only clones an `Arc`, so contention is brief.

use crate::cache::entry::StoredResponse;
use crate::metrics::Metrics;
use lru::LruCache;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub struct CacheStore {
    inner: Mutex<Inner>,
    /// Hard upper bound on `Inner::bytes`.
    max_bytes: u64,
    /// In-flight fetches, keyed by cache key, for request coalescing.
    /// The leader holds a `watch::Sender`; followers clone the
    /// `Receiver` and await it.  When the leader finishes it drops the
    /// sender (closing the channel), which wakes every follower.
    inflight: Mutex<HashMap<String, watch::Receiver<()>>>,
    metrics: Arc<Metrics>,
}

struct Inner {
    map: LruCache<String, Arc<StoredResponse>>,
    /// Running sum of every held entry's `size()`.
    bytes: u64,
}

/// Whether this request leads a fetch for its key or follows one
/// already in flight.  See [`CacheStore::begin_fetch`].
pub enum FetchRole {
    /// No fetch was in flight: this request leads it.  Hold the guard
    /// until the response is stored; dropping it wakes any followers.
    Leader(LeaderGuard),
    /// A fetch is already in flight: await this, then re-check the
    /// cache.
    Follower(watch::Receiver<()>),
}

/// RAII marker for the in-flight leader.  Dropping it removes the
/// in-flight entry and (via the contained sender) wakes followers,
/// whether the fetch succeeded, was uncacheable, or the task was
/// dropped mid-flight.
pub struct LeaderGuard {
    store: Arc<CacheStore>,
    key: String,
    // Dropping the sender closes the watch channel, which is the
    // signal followers wait on.  Never read directly.
    _tx: watch::Sender<()>,
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        self.store
            .inflight
            .lock()
            .expect("cache inflight mutex")
            .remove(&self.key);
    }
}

impl CacheStore {
    pub fn new(max_bytes: u64, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(CacheStore {
            // Unbounded by count; the byte budget is enforced here.
            inner: Mutex::new(Inner {
                map: LruCache::unbounded(),
                bytes: 0,
            }),
            max_bytes,
            inflight: Mutex::new(HashMap::new()),
            metrics,
        })
    }

    /// Claim or join the in-flight fetch for `key`.  The first caller
    /// becomes the [`FetchRole::Leader`]; concurrent callers become
    /// [`FetchRole::Follower`]s and should await the returned receiver,
    /// then re-run `lookup` (which serves the leader's stored response,
    /// or falls back to fetching themselves if it was uncacheable).
    pub fn begin_fetch(self: &Arc<Self>, key: &str) -> FetchRole {
        let mut inflight = self.inflight.lock().expect("cache inflight mutex");
        if let Some(rx) = inflight.get(key) {
            FetchRole::Follower(rx.clone())
        } else {
            let (tx, rx) = watch::channel(());
            inflight.insert(key.to_owned(), rx);
            FetchRole::Leader(LeaderGuard {
                store: self.clone(),
                key: key.to_owned(),
                _tx: tx,
            })
        }
    }

    /// Look up a key, bumping its recency.  Returns the shared entry
    /// (freshness is judged by the caller).
    pub fn get(&self, key: &str) -> Option<Arc<StoredResponse>> {
        let mut inner = self.inner.lock().expect("cache mutex");
        inner.map.get(key).cloned()
    }

    /// Store an entry, evicting LRU entries until the byte budget is
    /// satisfied.  A single object larger than the whole budget is
    /// refused rather than stored and immediately evicted.
    pub fn insert(&self, key: String, entry: Arc<StoredResponse>) {
        let size = entry.size() as u64;
        if size > self.max_bytes {
            return;
        }
        let mut inner = self.inner.lock().expect("cache mutex");
        if let Some(old) = inner.map.put(key, entry) {
            inner.bytes = inner.bytes.saturating_sub(old.size() as u64);
        }
        inner.bytes += size;
        while inner.bytes > self.max_bytes && inner.map.len() > 1 {
            match inner.map.pop_lru() {
                Some((_, evicted)) => {
                    inner.bytes =
                        inner.bytes.saturating_sub(evicted.size() as u64);
                    self.metrics
                        .cache_evictions
                        .fetch_add(1, Ordering::Relaxed);
                }
                None => break,
            }
        }
        self.metrics.cache_stores.fetch_add(1, Ordering::Relaxed);
    }

    /// Drop an entry (used when a lookup finds it stale).
    pub fn remove(&self, key: &str) {
        let mut inner = self.inner.lock().expect("cache mutex");
        if let Some(old) = inner.map.pop(key) {
            inner.bytes = inner.bytes.saturating_sub(old.size() as u64);
        }
    }

    /// Remove every entry that is no longer fresh as of `now`.
    pub fn evict_expired(&self, now: Instant) {
        let mut inner = self.inner.lock().expect("cache mutex");
        let stale: Vec<String> = inner
            .map
            .iter()
            .filter(|(_, e)| !e.is_fresh(now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            if let Some(old) = inner.map.pop(&k) {
                inner.bytes = inner.bytes.saturating_sub(old.size() as u64);
                self.metrics.cache_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Live (entry count, total bytes) for the gauges.
    pub fn stats(&self) -> (u64, u64) {
        let inner = self.inner.lock().expect("cache mutex");
        (inner.map.len() as u64, inner.bytes)
    }
}

/// Spawn the background sweeper: every 60 s drop stale entries and
/// refresh the `cache_entries` / `cache_bytes` gauges.  Mirrors
/// `rate_limit::spawn_eviction_task`.
pub fn spawn_cache_eviction_task(
    store: Arc<CacheStore>,
    metrics: Arc<Metrics>,
) -> tokio::task::JoinHandle<()> {
    crate::task::spawn_supervised("cache.eviction", async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        // Skip the immediate tick; nothing to sweep at startup.
        tick.tick().await;
        loop {
            tick.tick().await;
            store.evict_expired(Instant::now());
            let (entries, bytes) = store.stats();
            metrics.cache_entries.store(entries, Ordering::Relaxed);
            metrics.cache_bytes.store(bytes, Ordering::Relaxed);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::StatusCode;
    use hyper::header::HeaderMap;

    fn entry(
        body_len: usize,
        lifetime_secs: u64,
        at: Instant,
    ) -> Arc<StoredResponse> {
        Arc::new(StoredResponse::new(
            StatusCode::OK,
            &HeaderMap::new(),
            Bytes::from(vec![b'x'; body_len]),
            Duration::from_secs(lifetime_secs),
            Duration::ZERO,
            vec![],
            at,
        ))
    }

    #[test]
    fn get_returns_inserted_entry() {
        let m = Arc::new(Metrics::new());
        let store = CacheStore::new(1024, m);
        let t0 = Instant::now();
        store.insert("k".into(), entry(10, 60, t0));
        assert!(store.get("k").is_some());
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn lru_eviction_keeps_under_byte_budget() {
        let m = Arc::new(Metrics::new());
        // Budget fits two 100-byte entries but not three.
        let store = CacheStore::new(250, m.clone());
        let t0 = Instant::now();
        store.insert("a".into(), entry(100, 60, t0));
        store.insert("b".into(), entry(100, 60, t0));
        // Touch "a" so "b" becomes least-recently-used.
        let _ = store.get("a");
        store.insert("c".into(), entry(100, 60, t0));
        // "b" should have been evicted to stay under 250 bytes.
        assert!(store.get("a").is_some());
        assert!(store.get("c").is_some());
        assert!(store.get("b").is_none());
        assert_eq!(m.cache_evictions.load(Ordering::Relaxed), 1);
        let (entries, bytes) = store.stats();
        assert_eq!(entries, 2);
        assert_eq!(bytes, 200);
    }

    #[test]
    fn object_larger_than_budget_is_refused() {
        let m = Arc::new(Metrics::new());
        let store = CacheStore::new(50, m);
        let t0 = Instant::now();
        store.insert("big".into(), entry(100, 60, t0));
        assert!(store.get("big").is_none());
        assert_eq!(store.stats(), (0, 0));
    }

    #[test]
    fn evict_expired_drops_stale_entries() {
        let m = Arc::new(Metrics::new());
        let store = CacheStore::new(1024, m);
        let t0 = Instant::now();
        store.insert("fresh".into(), entry(10, 60, t0));
        store.insert("stale".into(), entry(10, 5, t0));
        store.evict_expired(t0 + Duration::from_secs(10));
        assert!(store.get("fresh").is_some());
        assert!(store.get("stale").is_none());
    }

    #[test]
    fn reinsert_same_key_does_not_double_count_bytes() {
        let m = Arc::new(Metrics::new());
        let store = CacheStore::new(1024, m);
        let t0 = Instant::now();
        store.insert("k".into(), entry(100, 60, t0));
        store.insert("k".into(), entry(40, 60, t0));
        assert_eq!(store.stats(), (1, 40));
    }

    #[test]
    fn single_flight_assigns_leader_then_followers() {
        let m = Arc::new(Metrics::new());
        let store = CacheStore::new(1024, m);
        let lead = store.begin_fetch("k");
        assert!(matches!(lead, FetchRole::Leader(_)));
        // A concurrent request for the same key follows.
        assert!(matches!(store.begin_fetch("k"), FetchRole::Follower(_)));
        // A different key leads its own fetch.
        assert!(matches!(store.begin_fetch("other"), FetchRole::Leader(_)));
        // Once the leader finishes, the key is claimable again.
        drop(lead);
        assert!(matches!(store.begin_fetch("k"), FetchRole::Leader(_)));
    }
}
