// HTTP response cache (RFC 9111), Phase 1.
//
// A single process-wide, byte-bounded LRU `CacheStore` holds buffered
// responses; each cache-enabled location carries a compiled
// `CachePolicy` that decides cacheability, builds the cache key, and
// drives read-through/write-through at the dispatch site.  The store is
// shared across locations and carried forward across SIGHUP so entries
// survive a reload; policies are rebuilt with the router.
//
// See `src/listener/service.rs` for the dispatch-site integration and
// `docs` for the operator-facing `cache { }` config.

mod entry;
mod key;
mod policy;
mod store;

pub use entry::StoredResponse;
pub use policy::{CachePolicy, Lookup, RequestCacheControl};
pub use store::{CacheStore, FetchRole, spawn_cache_eviction_task};
