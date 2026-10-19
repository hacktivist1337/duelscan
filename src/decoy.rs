//! Live decoy/deception detection.
//!
//! Some targets (WAFs, IDS/IPS, portspoof-style defenses) notice a fast
//! port scan and start answering EVERY probed port with a fake SYN-ACK, to
//! poison the scanner's results. The tell isn't visible until you're
//! mid-scan: a target that's genuinely wide open looks identical, probe by
//! probe, to one that's lying - the only signal is "this is already way
//! more open ports than is plausible, and it's still climbing."
//!
//! DecoyTracker is shared between an engine's RX side (which reports each
//! confirmed open port as it's confirmed) and its TX side (which checks,
//! before sending each further probe, whether the target it's about to
//! probe has already been flagged and - if so - skips it instead of wasting
//! the rest of that target's probes). Once an IP crosses the threshold it
//! stays flagged for the rest of that pass; main.rs reads the final flagged
//! set back out once the pass's result channel closes, discards whatever
//! partial results that pass found for those IPs (untrustworthy by
//! construction - that's WHY they got flagged), and requeues them for a
//! second pass at a different rate with a fresh tracker.
//!
//! Zero overhead when disabled: callers hold an `Option<Arc<DecoyTracker>>`
//! and skip straight past a `None` check, no locking at all.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

pub struct DecoyTracker {
    threshold: u32,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    open_counts: HashMap<Ipv4Addr, u32>,
    flagged: HashSet<Ipv4Addr>,
}

impl DecoyTracker {
    pub fn new(threshold: u32) -> Arc<Self> {
        Arc::new(DecoyTracker {
            threshold,
            inner: Mutex::new(Inner::default()),
        })
    }

    /// Call when a probe confirms an open port for `ip`. Updates the live
    /// count and flags the IP once it reaches the threshold (>=). Returns
    /// true exactly when THIS call is the one that newly crossed the
    /// threshold, so the caller can react immediately (emit the ip as
    /// flagged right away) instead of discovering it later on a timer.
    pub fn record_hit(&self, ip: Ipv4Addr) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let count = inner.open_counts.entry(ip).or_insert(0);
        *count += 1;
        if *count >= self.threshold {
            inner.flagged.insert(ip)
        } else {
            false
        }
    }

    /// Cheap check the TX side makes before spending a probe on `ip`.
    pub fn is_flagged(&self, ip: Ipv4Addr) -> bool {
        self.inner.lock().unwrap().flagged.contains(&ip)
    }
}
