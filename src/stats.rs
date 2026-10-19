//! Shared probe-level counters, reported as a single summary line when not
//! in -silent mode. This tracks the health of the *send/connect attempts*
//! themselves (did the OS let us even try?), which is a different axis from
//! "how many open ports did we find" - a scan can transmit perfectly and
//! still find nothing open, or it can find real opens while also silently
//! dropping some probes to a full socket buffer or a blown fd limit. Both
//! engines (synscan, connect) report into the same counters so main.rs can
//! print one consistent line regardless of which one ran.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct ScanStats {
    pub attempted: AtomicU64,
    pub errors: AtomicU64,
}

impl ScanStats {
    pub fn new() -> Arc<Self> {
        Arc::new(ScanStats {
            attempted: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn record_attempt(&self) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// (attempted, errored, succeeded) as a final snapshot. Call only after
    /// the engine has fully finished (i.e. after its result channel closes).
    pub fn snapshot(&self) -> (u64, u64, u64) {
        let attempted = self.attempted.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        (attempted, errors, attempted.saturating_sub(errors))
    }
}
