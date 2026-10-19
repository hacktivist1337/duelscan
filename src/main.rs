mod banner;
mod cli;
mod connect;
mod decoy;
mod stats;
mod synscan;
mod targets;
mod ulimit;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufWriter, IsTerminal, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::exit;
use std::sync::Arc;
use std::time::{Duration, Instant};

use decoy::DecoyTracker;
use stats::ScanStats;
use synscan::IpOutcome;
use targets::Target;

// Per-engine defaults for -threads when the user doesn't pass it. These live
// on genuinely different scales: a SYN TX thread is a long-lived raw socket
// doing pure packet construction (a handful is plenty - the real throughput
// knob is -rate, not thread count), while a connect-scan "thread" is really
// just an in-flight TCP handshake attempt, where thousands of concurrent
// ones is normal (same ballpark as rustscan's own default batch size).
const DEFAULT_SYN_THREADS: usize = 4;
const DEFAULT_CONNECT_THREADS: usize = 4000;
const DEFAULT_RESOLVER_THREADS: usize = 200;
const FD_SAFETY_MARGIN: u64 = 100; // stdio, listener fds, etc.
const FAILED_PORTS_FILE: &str = "failed_ports.txt";

fn eprintln_err(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {}", msg);
    exit(1);
}

/// Resolves -list: if it names an existing file, read its lines as before.
/// If it's not a file (or -list wasn't given), fall back to stdin, UNLESS
/// the value given isn't a path at all - in which case treat the value
/// itself as the one target ("-list hackerone.com" with no such file in the
/// current directory just scans that one host).
fn read_raw_lines(cfg: &cli::Config) -> Vec<String> {
    if let Some(value) = &cfg.list {
        if Path::new(value).is_file() {
            let f = File::open(value)
                .unwrap_or_else(|e| eprintln_err(format!("cannot open -list '{}': {}", value, e)));
            return io::BufReader::new(f)
                .lines()
                .filter_map(|l| l.ok())
                .collect();
        }
        // Not a file on disk: treat the argument itself as a single literal
        // target line, cleaned downstream exactly like a file line would be.
        return vec![value.clone()];
    }

    if !io::stdin().is_terminal() {
        // No -list given, and stdin is piped/redirected (not an interactive
        // terminal with nothing coming): read targets from it. If stdin IS a
        // terminal, we deliberately do NOT block waiting for input - the
        // caller is expected to be using -cidr alone in that case.
        return io::stdin().lock().lines().filter_map(|l| l.ok()).collect();
    }

    Vec::new()
}

struct OutputSink {
    silent: bool,
    file: Option<BufWriter<File>>,
}

impl OutputSink {
    fn new(cfg: &cli::Config) -> Self {
        let file = cfg.output.as_ref().map(|path| {
            let f = File::create(path).unwrap_or_else(|e| eprintln_err(format!("cannot create -o '{}': {}", path, e)));
            BufWriter::new(f)
        });
        OutputSink { silent: cfg.silent, file }
    }

    fn banner(&mut self, msg: &str) {
        if !self.silent {
            eprintln!("{}", msg);
        }
    }

    fn result_line(&mut self, line: &str) {
        println!("{}", line);
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{}", line);
        }
    }

    fn flush(&mut self) {
        if let Some(f) = self.file.as_mut() {
            let _ = f.flush();
        }
    }
}

/// Runs one full pass (phase 1 or phase 2) over `unique_ips`, printing each
/// TARGET's (not each IP's) result the moment every IP belonging to that
/// target has been accounted for in THIS pass - so a 10-host list prints
/// host 1's result as soon as host 1 is done, not after host 10 finishes.
/// A target with two IPs only prints once both are in, already merged and
/// deduped (a port found on either IP appears once, in ascending order).
///
/// Returns (lines printed, IPs that got -decoy-flagged this pass).
#[allow(clippy::too_many_arguments)]
fn run_pass(
    unique_ips: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    can_raw: bool,
    syn_rate_pps: u64,
    connect_concurrency: usize,
    requested_syn_threads: Option<usize>,
    retry: u32,
    timeout_ms: u64,
    decoy_threshold: Option<u32>,
    probe_stats: Arc<ScanStats>,
    ip_to_targets: &HashMap<Ipv4Addr, Vec<usize>>,
    all_targets: &[Target],
    out: &mut OutputSink,
) -> (u64, HashSet<Ipv4Addr>) {
    if unique_ips.is_empty() {
        return (0, HashSet::new());
    }

    let total_probes = unique_ips.len() as u64 * ports.len() as u64;
    let decoy_tracker: Option<Arc<DecoyTracker>> = decoy_threshold.map(DecoyTracker::new);

    let rx: std::sync::mpsc::Receiver<IpOutcome> = if can_raw {
        let syn_threads = requested_syn_threads
            .unwrap_or(DEFAULT_SYN_THREADS)
            .min(total_probes.max(1) as usize)
            .max(1);
        let syn_cfg = synscan::SynScanConfig {
            src_port: 61337,
            threads: syn_threads,
            rate_pps: syn_rate_pps,
            grace_period: Duration::from_millis(timeout_ms.max(500)),
            retry,
        };
        synscan::run(unique_ips.clone(), ports, syn_cfg, probe_stats, decoy_tracker.clone())
    } else {
        let conn_cfg = connect::ConnectScanConfig {
            concurrency: connect_concurrency.max(1),
            timeout: Duration::from_millis(timeout_ms),
            retry,
        };
        connect::run(unique_ips.clone(), ports, conn_cfg, probe_stats, decoy_tracker.clone())
    };

    // How many of THIS pass's IPs each display name still has outstanding -
    // a display prints only once every one of its ips (in this pass) has
    // reported in, merging their ports as they arrive.
    let mut display_remaining: HashMap<String, u32> = HashMap::new();
    let mut display_ports: HashMap<String, std::collections::BTreeSet<u16>> = HashMap::new();
    for &ip in &unique_ips {
        if let Some(indices) = ip_to_targets.get(&ip) {
            for &idx in indices {
                *display_remaining
                    .entry(all_targets[idx].display.clone())
                    .or_insert(0) += 1;
            }
        }
    }

    let mut found = 0u64;
    let mut flagged_ips: HashSet<Ipv4Addr> = HashSet::new();

    for (ip, outcome) in rx {
        match outcome {
            Some(ports) => {
                if let Some(indices) = ip_to_targets.get(&ip) {
                    for &idx in indices {
                        let name = &all_targets[idx].display;
                        display_ports
                            .entry(name.clone())
                            .or_default()
                            .extend(ports.iter().copied());
                    }
                }
            }
            None => {
                flagged_ips.insert(ip);
            }
        }

        // This ip is accounted for either way (normal result or flagged) -
        // decrement every display name it belongs to and print whichever
        // ones just reached zero outstanding ips.
        if let Some(indices) = ip_to_targets.get(&ip) {
            let names: Vec<String> = indices
                .iter()
                .map(|&idx| all_targets[idx].display.clone())
                .collect();
            for name in names {
                if let Some(rem) = display_remaining.get_mut(&name) {
                    *rem = rem.saturating_sub(1);
                    if *rem == 0 {
                        if let Some(ports) = display_ports.remove(&name) {
                            for port in ports {
                                out.result_line(&format!("{}:{}", name, port));
                                found += 1;
                            }
                        }
                        display_remaining.remove(&name);
                    }
                }
            }
        }
    }

    (found, flagged_ips)
}

fn main() {
    let cfg = cli::parse_args();

    if !cfg.silent {
        banner::print();
    }

    let ports = targets::parse_ports(&cfg.ports).unwrap_or_else(|e| eprintln_err(e));

    let mut out = OutputSink::new(&cfg);
    let start = Instant::now();

    let raw_lines = read_raw_lines(&cfg);
    let mut host_strings: Vec<String> = raw_lines
        .iter()
        .filter_map(|l| targets::clean_line(l))
        .collect();

    if host_strings.is_empty() && cfg.cidr.is_none() {
        eprintln_err("no targets given (empty -list/stdin and no -cidr)");
    }

    out.banner(&format!(
        "duelscan: {} raw target line(s) parsed, resolving...",
        host_strings.len()
    ));

    let resolver_threads = cfg.threads.unwrap_or(DEFAULT_RESOLVER_THREADS).min(512).max(16);
    host_strings.sort();
    host_strings.dedup();
    let (mut all_targets, mut ip_to_targets, mut unique_ips): (
        Vec<Target>,
        HashMap<Ipv4Addr, Vec<usize>>,
        Vec<Ipv4Addr>,
    ) = targets::resolve_all(host_strings, resolver_threads);

    if let Some(cidr) = &cfg.cidr {
        // -cidr accepts either a literal CIDR ("192.168.0.0/24") or a path
        // to a file listing many, one per line.
        let cidr_ips = targets::resolve_cidr_arg(cidr).unwrap_or_else(|e| eprintln_err(e));
        let cidr_targets = targets::ips_as_targets(cidr_ips);
        for t in cidr_targets {
            let idx = all_targets.len();
            ip_to_targets.entry(t.ip).or_default().push(idx);
            all_targets.push(t);
        }
        unique_ips = ip_to_targets.keys().copied().collect();
    }

    if unique_ips.is_empty() {
        eprintln_err("no targets resolved to an IPv4 address");
    }

    let total_probes = unique_ips.len() as u64 * ports.len() as u64;
    out.banner(&format!(
        "duelscan: {} unique IPv4 target(s) x {} port(s) = {} probes",
        unique_ips.len(),
        ports.len(),
        total_probes
    ));

    // -ulimit is applied unconditionally, before we even know which engine
    // we'll use - same as rustscan, which raises it at startup regardless of
    // scan technique.
    let (soft_before, _hard_before) = ulimit::get_nofile_limits();
    let effective_limit = match cfg.ulimit {
        Some(requested) => match ulimit::raise_nofile_limit(requested) {
            Ok(new_soft) => {
                out.banner(&format!(
                    "duelscan: raised RLIMIT_NOFILE {} -> {}",
                    soft_before, new_soft
                ));
                new_soft
            }
            Err(e) => {
                out.banner(&format!(
                    "duelscan: could not raise RLIMIT_NOFILE to {} ({}), staying at {}",
                    requested, e, soft_before
                ));
                soft_before
            }
        },
        None => soft_before,
    };

    let probe_stats = ScanStats::new();
    let can_raw = synscan::raw_sockets_available();
    if can_raw {
        out.banner("duelscan: raw sockets available -> stateless SYN scan");
    } else {
        out.banner("duelscan: no raw socket permission (need root/CAP_NET_RAW) -> async connect-scan fallback");
    }

    let safe_concurrency = effective_limit.saturating_sub(FD_SAFETY_MARGIN).max(1);
    let phase1_requested_conn = cfg.threads.unwrap_or(DEFAULT_CONNECT_THREADS) as u64;
    let phase1_concurrency = phase1_requested_conn.min(safe_concurrency) as usize;
    if !can_raw && phase1_requested_conn > safe_concurrency {
        out.banner(&format!(
            "duelscan: -threads {} exceeds the safe fd budget ({} after margin) \
             for the current ulimit ({}) -> clamped to {} to avoid false negatives. \
             Pass -ulimit <n> to raise the ceiling instead.",
            phase1_requested_conn, safe_concurrency, effective_limit, phase1_concurrency
        ));
    }

    let decoy_threshold = if cfg.decoy { Some(cfg.decoy_threshold) } else { None };

    // --- Phase 1: the real scan, at the user's normal -rate. Prints each
    // target's result as soon as that target (all its ips) is done. ---
    let (found1, flagged) = run_pass(
        unique_ips,
        ports.clone(),
        can_raw,
        cfg.rate_pps,
        phase1_concurrency,
        cfg.threads,
        cfg.retry,
        cfg.timeout_ms,
        decoy_threshold,
        probe_stats.clone(),
        &ip_to_targets,
        &all_targets,
        &mut out,
    );
    let mut found = found1;

    // --- Phase 2 (only with -decoy, and only for targets flagged in phase 1): ---
    if cfg.decoy && !flagged.is_empty() {
        out.banner(&format!(
            "duelscan: {} target(s) hit >= {} open ports mid-scan (possible deception) \
             -> requeued for a slower rescan at -decoy-rate {}",
            flagged.len(),
            cfg.decoy_threshold,
            cfg.decoy_rate
        ));

        let flagged_ips_vec: Vec<Ipv4Addr> = flagged.iter().copied().collect();
        let phase2_concurrency = (cfg.decoy_rate.max(1)).min(safe_concurrency) as usize;

        let (found2, still_flagged) = run_pass(
            flagged_ips_vec,
            ports,
            can_raw,
            cfg.decoy_rate,
            phase2_concurrency,
            cfg.threads,
            cfg.retry,
            cfg.timeout_ms,
            decoy_threshold,
            probe_stats.clone(),
            &ip_to_targets,
            &all_targets,
            &mut out,
        );
        found += found2;

        if !still_flagged.is_empty() {
            let mut failed_names: Vec<String> = Vec::new();
            for ip in &still_flagged {
                if let Some(indices) = ip_to_targets.get(ip) {
                    for &idx in indices {
                        failed_names.push(all_targets[idx].display.clone());
                    }
                }
            }
            failed_names.sort();
            failed_names.dedup();

            for name in &failed_names {
                out.banner(&format!(
                    "duelscan: FAILED (still >= {} open ports at -decoy-rate, likely deception): {}",
                    cfg.decoy_threshold, name
                ));
            }

            match File::create(FAILED_PORTS_FILE) {
                Ok(f) => {
                    let mut w = BufWriter::new(f);
                    for name in &failed_names {
                        let _ = writeln!(w, "{}", name);
                    }
                    let _ = w.flush();
                }
                Err(e) => {
                    out.banner(&format!(
                        "duelscan: could not write {}: {}",
                        FAILED_PORTS_FILE, e
                    ));
                }
            }
        }
    }

    out.flush();

    let (attempted, errored, succeeded) = probe_stats.snapshot();
    out.banner(&format!(
        "duelscan: {} probes sent, {} errored, {} succeeded",
        attempted, errored, succeeded
    ));
    out.banner(&format!(
        "duelscan: done in {:.2}s, {} open result(s)",
        start.elapsed().as_secs_f64(),
        found
    ));
}
