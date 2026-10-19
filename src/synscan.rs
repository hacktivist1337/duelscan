//! Stateless SYN scan engine.
//!
//! The core trick (popularized by masscan/zmap, not something exotic or
//! secret) is to never keep per-probe connection state. Instead, the initial
//! TCP sequence number we send is a keyed hash of (dst_ip, dst_port,
//! src_port). When a SYN-ACK comes back, we recompute that same hash from the
//! response's fields and check it against (ack_number - 1). If it matches, we
//! know with near-certainty this is a reply to a probe *we* actually sent,
//! without ever having stored that probe anywhere. That's what lets the
//! sender run at line rate with unbounded "concurrency" and no hash table to
//! maintain, which is the actual source of masscan/zmap's speed advantage
//! over connect()-based scanners like a naive rustscan run - not a faster
//! inner loop, but an O(1)-memory, lock-free architecture.
//!
//! Practical note for whoever runs this: the local kernel's own TCP stack
//! doesn't know we sent these SYNs (we bypassed it via a raw socket), so when
//! a SYN-ACK arrives on our source port, the kernel may fire back an
//! unsolicited RST before/after we've already recorded the result. That's
//! harmless to accuracy (we already saw the SYN-ACK) but if you want a fully
//! clean handshake on the wire, add e.g.:
//!   iptables -A OUTPUT -p tcp --sport <SRC_PORT> --tcp-flags RST RST -j DROP
//! masscan and zmap have the exact same requirement/caveat.
//!
//! Transmit-side sharding is over the FLAT (ip, port) probe space, not over
//! IPs. Sharding by IP meant a single-target, full-port-range scan (one IP,
//! 65535 ports - the common "deep scan one host" case) only ever kept
//! exactly one TX thread busy no matter what -threads was set to; every
//! other thread found zero IPs in its slice and exited immediately, so
//! -threads silently did nothing except pay for extra thread/raw-socket
//! setup. Flattening to probe-index = ip_index * n_ports + port_index and
//! striding threads over THAT fixes it: every thread gets a real, even
//! fraction of the work regardless of how many unique targets there are.
//!
//! Per-IP streaming: results are NOT buffered until the whole scan ends.
//! Every target IP has a "remaining probes" counter, initialized to
//! n_ports and decremented as each of its probes is sent (or skipped, if
//! -decoy flagged it). Once an IP's counter hits zero, we know its sends
//! are done; after one more grace period (for in-flight responses) with no
//! new activity, that IP is finalized and reported through the results
//! channel immediately - independent of whatever's still happening with
//! every other target. A target flagged by -decoy is reported the instant
//! it crosses the threshold, even faster (no need to wait for its sends to
//! finish first, since we already know to discard it).

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::transport::{self, TransportChannelType::Layer4, TransportProtocol::Ipv4 as ProtoIpv4};

use crate::decoy::DecoyTracker;
use crate::stats::ScanStats;

pub struct SynScanConfig {
    pub src_port: u16,
    pub threads: usize,
    pub rate_pps: u64, // 0 = uncapped (see cli.rs help: not recommended)
    pub grace_period: Duration,
    /// Extra attempts for a probe whose send_to() call itself errors (e.g.
    /// ENOBUFS from sending faster than the NIC/driver can drain). Does NOT
    /// apply to anything about the target's response - there's no such
    /// thing as a "failed" SYN-ACK to retry, only a failed local send.
    pub retry: u32,
}

/// One finalized target: `Some(ports)` for a normal completion (ports may be
/// empty - that's a legitimate "found nothing" result, not an error), or
/// `None` if -decoy flagged this IP as likely deception (caller should
/// discard whatever partial data it had and requeue it instead of trusting
/// these results).
pub type IpOutcome = (Ipv4Addr, Option<BTreeSet<u16>>);

/// Quick capability probe: can we actually open a raw TCP socket here?
/// (Requires root / CAP_NET_RAW on Linux.) Used to decide whether to use the
/// fast SYN path or fall back to a connect-scan.
pub fn raw_sockets_available() -> bool {
    transport::transport_channel(1024, Layer4(ProtoIpv4(IpNextHeaderProtocols::Tcp))).is_ok()
}

#[inline]
fn cookie(secret: u64, ip: Ipv4Addr, port: u16, src_port: u16) -> u32 {
    let ip_bits: u64 = u32::from(ip) as u64;
    let mut h = secret;
    h ^= ip_bits.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= (port as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    h ^= (src_port as u64).wrapping_mul(0x1656_67B1_9E37_79F9);
    h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^= h >> 33;
    (h as u32) | 1
}

/// Finds the local IPv4 address the kernel would use to reach `dst`, via the
/// standard "connect() a UDP socket, then getsockname()" trick. This never
/// puts a packet on the wire - UDP connect() is a purely local routing-table
/// lookup - it's just the simplest portable way to answer "which of my NICs
/// faces that destination?", which we need for a correct TCP checksum.
fn local_src_ip_for(dst: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect((dst, 80))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

/// Linear backoff before a resend, capped low - just enough to give a
/// momentarily full send queue a chance to drain, not a real "wait for the
/// network" delay.
#[inline]
fn retry_backoff(attempt: u32) -> Duration {
    Duration::from_millis((attempt as u64 * 2).min(50))
}

/// Shared per-IP send progress: how many of this IP's probes are still
/// unsent, and (once that hits zero) when the last one was handled. TX
/// threads only ever decrement; the RX thread only ever reads.
struct SendProgress {
    remaining: Mutex<HashMap<Ipv4Addr, u32>>,
    done_at: Mutex<HashMap<Ipv4Addr, Instant>>,
}

impl SendProgress {
    fn new(ips: &[Ipv4Addr], n_ports: u32) -> Self {
        let mut m = HashMap::with_capacity(ips.len());
        for &ip in ips {
            m.insert(ip, n_ports);
        }
        SendProgress {
            remaining: Mutex::new(m),
            done_at: Mutex::new(HashMap::new()),
        }
    }

    /// Call once per probe actually handled (sent or given up on after
    /// retries) for `ip`. Never call this for a probe skipped because the
    /// ip was already -decoy-flagged - that ip's outcome is already decided.
    fn mark_one_handled(&self, ip: Ipv4Addr) {
        let hit_zero = {
            let mut rem = self.remaining.lock().unwrap();
            match rem.get_mut(&ip) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                    *count == 0
                }
                _ => false,
            }
        };
        if hit_zero {
            self.done_at.lock().unwrap().insert(ip, Instant::now());
        }
    }

    fn done_since(&self, ip: Ipv4Addr) -> Option<Instant> {
        self.done_at.lock().unwrap().get(&ip).copied()
    }
}

/// Launches the scan in the background and returns a channel of per-IP
/// outcomes, each sent as soon as that specific IP is finalized (not
/// buffered until the whole scan ends). The channel closes once every
/// target IP has been accounted for.
pub fn run(
    unique_ips: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    cfg: SynScanConfig,
    stats: Arc<ScanStats>,
    decoy: Option<Arc<DecoyTracker>>,
) -> Receiver<IpOutcome> {
    let (result_tx, result_rx) = channel::<IpOutcome>();

    if unique_ips.is_empty() || ports.is_empty() {
        return result_rx;
    }

    let secret: u64 = rand::random();
    let src_port = cfg.src_port;
    let threads = cfg.threads.max(1);
    let retry = cfg.retry;
    let source_ip = local_src_ip_for(unique_ips[0]).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let n_ports = ports.len() as u64;
    let total_probes = unique_ips.len() as u64 * n_ports;

    let progress = Arc::new(SendProgress::new(&unique_ips, ports.len() as u32));
    let all_ips = Arc::new(unique_ips.clone());
    let all_ports = Arc::new(ports);
    let tx_active = Arc::new(AtomicU64::new(threads as u64));

    // --- RX thread: validates SYN-ACKs, tracks decoy state, and finalizes
    // + emits each IP's outcome as soon as it's known (flagged immediately,
    // or normally complete after its sends finish + one grace period). ---
    {
        let tx_active = Arc::clone(&tx_active);
        let progress = Arc::clone(&progress);
        let grace = cfg.grace_period;
        let result_tx = result_tx.clone();
        let decoy = decoy.clone();
        let target_ips = unique_ips;
        std::thread::spawn(move || {
            let (_sender, mut receiver) =
                match transport::transport_channel(1 << 20, Layer4(ProtoIpv4(IpNextHeaderProtocols::Tcp))) {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
            let mut iter = transport::tcp_packet_iter(&mut receiver);

            let mut open_ports: HashMap<Ipv4Addr, BTreeSet<u16>> = HashMap::new();
            let mut pending: std::collections::HashSet<Ipv4Addr> = target_ips.into_iter().collect();
            let mut force_deadline: Option<Instant> = None;
            // The finalization sweep below is O(pending.len()) - cheap once,
            // but NOT something to redo on every single packet when
            // thousands of targets are still pending: at high packet rates
            // that starves this thread of time to actually drain the socket,
            // which is exactly the kernel-receive-buffer-overflow failure
            // mode this engine already has to watch for. Cap it to a fixed
            // cadence instead, independent of how often packets arrive.
            const SWEEP_INTERVAL: Duration = Duration::from_millis(50);
            let mut last_sweep = Instant::now();

            macro_rules! finalize {
                ($ip:expr, $outcome:expr) => {{
                    pending.remove(&$ip);
                    open_ports.remove(&$ip);
                    if result_tx.send(($ip, $outcome)).is_err() {
                        return; // receiver dropped, caller is done with us
                    }
                }};
            }

            loop {
                match iter.next_with_timeout(Duration::from_millis(150)) {
                    Ok(Some((tcp, src_addr))) => {
                        if let IpAddr::V4(src_ip4) = src_addr {
                            let flags = tcp.get_flags();
                            let is_synack = (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0);
                            if is_synack && tcp.get_destination() == src_port && pending.contains(&src_ip4) {
                                let expected = cookie(secret, src_ip4, tcp.get_source(), src_port);
                                if tcp.get_acknowledgement().wrapping_sub(1) == expected {
                                    let port = tcp.get_source();
                                    if let Some(d) = &decoy {
                                        if d.record_hit(src_ip4) {
                                            // Just crossed the threshold - discard and
                                            // report immediately, don't wait for its
                                            // sends to finish or for a grace period.
                                            finalize!(src_ip4, None);
                                            continue;
                                        }
                                    }
                                    open_ports.entry(src_ip4).or_default().insert(port);
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {}
                }

                // Sweep for IPs whose sends are done and whose grace period
                // has now elapsed - finalize and emit them right away. Rate
                // limited (see SWEEP_INTERVAL above) so a burst of incoming
                // packets can't turn this into the bottleneck.
                if last_sweep.elapsed() >= SWEEP_INTERVAL {
                    last_sweep = Instant::now();
                    let ready: Vec<Ipv4Addr> = pending
                        .iter()
                        .filter(|ip| matches!(progress.done_since(**ip), Some(t) if t.elapsed() >= grace))
                        .copied()
                        .collect();
                    for ip in ready {
                        let ports = open_ports.remove(&ip).unwrap_or_default();
                        finalize!(ip, Some(ports));
                    }
                }

                if pending.is_empty() {
                    break;
                }

                // Safety net: once every TX thread is done sending, give any
                // still-pending IPs (should be rare - e.g. one whose very
                // last probe is still in flight) one more combined grace
                // window, then force-finalize whatever's left so the engine
                // always terminates.
                if tx_active.load(Ordering::Relaxed) == 0 {
                    match force_deadline {
                        Some(d) if Instant::now() >= d => {
                            let remaining: Vec<Ipv4Addr> = pending.iter().copied().collect();
                            for ip in remaining {
                                let ports = open_ports.remove(&ip).unwrap_or_default();
                                finalize!(ip, Some(ports));
                            }
                        }
                        None => force_deadline = Some(Instant::now() + grace),
                        _ => {}
                    }
                }
            }
        });
    }

    // --- TX threads: each owns a stride over the FLAT (ip, port) probe
    // index space (probe_idx = ip_idx * n_ports + port_idx), not over IPs.
    // This is what makes -threads actually matter even for a single target.
    for t in 0..threads {
        let all_ips = Arc::clone(&all_ips);
        let all_ports = Arc::clone(&all_ports);
        let tx_active = Arc::clone(&tx_active);
        let stats = Arc::clone(&stats);
        let decoy = decoy.clone();
        let progress = Arc::clone(&progress);
        std::thread::spawn(move || {
            let send_result =
                transport::transport_channel(1 << 16, Layer4(ProtoIpv4(IpNextHeaderProtocols::Tcp)));
            let mut sender = match send_result {
                Ok((s, _)) => s,
                Err(_) => {
                    tx_active.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            };

            let per_packet_delay = if cfg.rate_pps > 0 {
                let per_thread_rate = (cfg.rate_pps / threads as u64).max(1);
                Some(Duration::from_nanos(1_000_000_000 / per_thread_rate))
            } else {
                None
            };

            let mut buf = [0u8; 20]; // bare TCP header, no options
            let mut probe_idx = t as u64;
            while probe_idx < total_probes {
                let ip = all_ips[(probe_idx / n_ports) as usize];
                let port = all_ports[(probe_idx % n_ports) as usize];

                // This target was already flagged (by this or another
                // thread's probe) - its outcome is already decided and
                // reported, so just skip the rest of its probes outright.
                if let Some(d) = &decoy {
                    if d.is_flagged(ip) {
                        probe_idx += threads as u64;
                        continue;
                    }
                }

                let mut attempt = 0u32;
                let mut sent_ok = false;
                loop {
                    attempt += 1;
                    let mut pkt = match MutableTcpPacket::new(&mut buf) {
                        Some(p) => p,
                        None => break,
                    };
                    pkt.set_source(src_port);
                    pkt.set_destination(port);
                    pkt.set_sequence(cookie(secret, ip, port, src_port));
                    pkt.set_acknowledgement(0);
                    pkt.set_data_offset(5);
                    pkt.set_reserved(0);
                    pkt.set_flags(TcpFlags::SYN);
                    pkt.set_window(64240);
                    pkt.set_urgent_ptr(0);
                    pkt.set_options(&[]);
                    let checksum = tcp::ipv4_checksum(&pkt.to_immutable(), &source_ip, &ip);
                    pkt.set_checksum(checksum);

                    if sender.send_to(pkt.to_immutable(), IpAddr::V4(ip)).is_ok() {
                        sent_ok = true;
                        break;
                    }
                    if attempt > retry {
                        break;
                    }
                    std::thread::sleep(retry_backoff(attempt));
                }
                stats.record_attempt();
                if !sent_ok {
                    stats.record_error();
                }
                progress.mark_one_handled(ip);

                if let Some(d) = per_packet_delay {
                    std::thread::sleep(d);
                }

                probe_idx += threads as u64;
            }

            tx_active.fetch_sub(1, Ordering::Relaxed);
        });
    }

    result_rx
}
