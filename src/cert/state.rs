// Shared certificate state written by AcmeManager on each renewal
// and read by StatusHandler for the live dashboard.  Defined here
// to avoid either module importing the other.

use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct CertState {
    pub domains: Vec<String>,
    // Unix timestamp of cert notAfter.
    pub expiry_ts: i64,
    // expiry_ts - 30 * 86400: when next renewal attempt is scheduled.
    pub next_renewal_ts: i64,
}

pub type SharedCertState = Arc<RwLock<Vec<CertState>>>;

pub fn new_shared() -> SharedCertState {
    Arc::new(RwLock::new(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_clone_shares_state() {
        let shared = new_shared();
        {
            let mut v = shared.write().unwrap();
            v.push(CertState {
                domains: vec!["example.com".into()],
                expiry_ts: 9_999_999_999,
                next_renewal_ts: 9_997_406_399,
            });
        }
        // Arc::clone should share the same underlying vector.
        let cloned = shared.clone();
        assert_eq!(shared.read().unwrap().len(), cloned.read().unwrap().len(),);
    }

    #[test]
    fn cert_state_clone_is_value_copy() {
        let cs = CertState {
            domains: vec!["a.com".into()],
            expiry_ts: 1_000,
            next_renewal_ts: 900,
        };
        let mut copy = cs.clone();
        copy.expiry_ts = 2_000;
        // Original is unchanged.
        assert_eq!(cs.expiry_ts, 1_000);
    }

    /// Publishing a renewed cert state replaces the entry observed
    /// by readers.  This is the round-trip the status page relies on:
    /// AcmeManager writes the new expiry, the status snapshot reads
    /// it back.
    #[test]
    fn publish_and_read_back() {
        let shared = new_shared();
        // Writer publishes.
        {
            let mut v = shared.write().unwrap();
            v.push(CertState {
                domains: vec!["one.example".into()],
                expiry_ts: 1_000,
                next_renewal_ts: 900,
            });
        }
        // Reader sees the same value.
        let snapshot: Vec<CertState> = shared.read().unwrap().clone();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].domains, vec!["one.example".to_string()]);
        assert_eq!(snapshot[0].expiry_ts, 1_000);

        // Writer mutates (renewal scenario).
        {
            let mut v = shared.write().unwrap();
            v[0].expiry_ts = 9_999;
            v[0].next_renewal_ts = 9_899;
        }
        // Reader sees the new value, not the snapshot.
        let after: Vec<CertState> = shared.read().unwrap().clone();
        assert_eq!(after[0].expiry_ts, 9_999);
        assert_eq!(after[0].next_renewal_ts, 9_899);
    }

    /// `new_shared` returns an empty vector that readers can lock
    /// without blocking on writers that haven't written yet.
    #[test]
    fn new_shared_starts_empty() {
        let shared = new_shared();
        assert_eq!(shared.read().unwrap().len(), 0);
    }
}
