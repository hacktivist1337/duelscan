//! Fallback scan engine for when raw sockets aren't available (no root /
//! CAP_NET_RAW). This is the same family of technique rustscan itself uses:
//! a large number of concurrent async TCP connect() attempts, bounded by a
//! semaphore sized to the configured concurrency so we don't blow past the
//! process's open-file-descriptor limit. It will never be as fast as a raw
//! SYN scan (it pays for a full handshake + socket teardown per probe), but
//! it needs no privileges and still parallelizes far beyond what a naive
//! sequential scanner would do.
//!
//! Per-IP streaming (see synscan.rs for the fuller rationale): each IP's
//! result is reported the moment it's known, not buffered until the whole
//! scan ends. Unlike the SYN engine, a connect-scan probe's outcome is known
//! synchronously the instant its own task finishes (no separate "wait for a
//! delayed response" phase - the task already waited out its own timeout
//! internally), so finalizing an IP just means "every task for this IP has
//! completed": no extra grace period needed, the last task to finish for a
//! given IP can finalize and emit it immediately.

use std::collections::{BTreeSet, HashMap};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::decoy::DecoyTracker;
use crate::stats::ScanStats;
use crate::synscan::IpOutcome;

pub struct ConnectScanConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    /// Extra attempts for a probe that hit a genuine local/OS error (fd
    /// exhaustion, network unreachable, ...). A "connection refused" is a
    /// real, conclusive answer (closed) and is never retried; neither is a
    /// plain timeout (no answer, not a failure).
    pub retry: u32,
}

#[inline]
fn retry_backoff(attempt: u32) -> Duration {
    Duration::from_millis((attempt as u64 * 2).min(50))
}

struct IpState {
    remaining: u32,
    ports: BTreeSet<u16>,
    finalized: bool,
}

pub fn run(
    unique_ips: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    cfg: ConnectScanConfig,
    stats: Arc<ScanStats>,
    decoy: Option<Arc<DecoyTracker>>,
) -> Receiver<IpOutcome> {
    let (result_tx, result_rx) = channel::<IpOutcome>();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(_) => return,
        };
        rt.block_on(async move {
            let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
            let n_ports = ports.len() as u32;
            let state: Arc<Mutex<HashMap<Ipv4Addr, IpState>>> = Arc::new(Mutex::new(
                unique_ips
                    .iter()
                    .map(|&ip| {
                        (
                            ip,
                            IpState {
                                remaining: n_ports,
                                ports: BTreeSet::new(),
                                finalized: false,
                            },
                        )
                    })
                    .collect(),
            ));
            let mut handles = Vec::with_capacity(unique_ips.len() * ports.len());

            for ip in unique_ips {
                for &port in &ports {
                    let sem = Arc::clone(&sem);
                    let result_tx = result_tx.clone();
                    let timeout = cfg.timeout;
                    let stats = Arc::clone(&stats);
                    let retry = cfg.retry;
                    let decoy = decoy.clone();
                    let state = Arc::clone(&state);
                    handles.push(tokio::spawn(async move {
                        // Already flagged this pass - don't bother spending
                        // a connect attempt (and a semaphore slot) on it;
                        // its outcome was already emitted when it got
                        // flagged, and nothing is tracking its "remaining"
                        // countdown anymore.
                        if let Some(d) = &decoy {
                            if d.is_flagged(ip) {
                                return;
                            }
                        }
                        let _permit = sem.acquire_owned().await.ok();
                        let addr = SocketAddr::new(IpAddr::V4(ip), port);

                        let mut attempt = 0u32;
                        let mut opened = false;
                        loop {
                            attempt += 1;
                            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                                Ok(Ok(_stream)) => {
                                    opened = true;
                                    break;
                                }
                                Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                                    // Closed. The probe worked; the answer
                                    // was just "no". Not a tool-level error,
                                    // never retried.
                                    break;
                                }
                                Ok(Err(_)) => {
                                    // A real local/OS-level failure (fd
                                    // exhaustion, network unreachable, ...).
                                    if attempt > retry {
                                        stats.record_error();
                                        break;
                                    }
                                    tokio::time::sleep(retry_backoff(attempt)).await;
                                    // loop again and retry
                                }
                                Err(_elapsed) => {
                                    // No response within the timeout
                                    // (filtered/dropped). Inconclusive, not
                                    // a tool error, never retried.
                                    break;
                                }
                            }
                        }
                        stats.record_attempt();

                        // Record the outcome and see if this was the probe
                        // that finishes (or flags) this IP. Keep the lock
                        // scope short and never hold it across an .await.
                        let mut just_flagged = false;
                        let mut finalize_now: Option<(Ipv4Addr, Option<BTreeSet<u16>>)> = None;
                        {
                            let mut map = state.lock().unwrap();
                            if let Some(st) = map.get_mut(&ip) {
                                if st.finalized {
                                    // Already flagged/finalized by another
                                    // task for this ip; nothing left to do.
                                } else {
                                    if opened {
                                        if let Some(d) = &decoy {
                                            if d.record_hit(ip) {
                                                just_flagged = true;
                                            }
                                        }
                                        if !just_flagged {
                                            st.ports.insert(port);
                                        }
                                    }
                                    if just_flagged {
                                        st.finalized = true;
                                        finalize_now = Some((ip, None));
                                    } else {
                                        st.remaining = st.remaining.saturating_sub(1);
                                        if st.remaining == 0 {
                                            st.finalized = true;
                                            finalize_now = Some((ip, Some(std::mem::take(&mut st.ports))));
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(outcome) = finalize_now {
                            let _ = result_tx.send(outcome);
                        }
                    }));
                }
            }

            for h in handles {
                let _ = h.await;
            }
        });
    });

    result_rx
}
