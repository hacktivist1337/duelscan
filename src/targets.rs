use std::collections::HashMap;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;

/// A single scan target: what to print (original hostname or IP) + the
/// resolved IPv4 address actually probed on the wire.
#[derive(Debug, Clone)]
pub struct Target {
    pub display: String,
    pub ip: Ipv4Addr,
}

/// Cleans up one raw line from scope.txt into a bare host/IP string.
///
/// Handles the messy real-world formats bug-bounty scope files tend to have:
///   example.com                              -> example.com
///   https://www.sub.example.com               -> www.sub.example.com
///   https://www.sub.example.com/some/path?x=1 -> www.sub.example.com
///   [www.sub.example.com](https://...)        -> www.sub.example.com   (markdown auto-link)
///   192.0.2.10                                -> 192.0.2.10
///   *.example.com                             -> example.com (wildcard scope -> base domain)
pub fn clean_line(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }

    // Markdown link: "[text](url)" -> take "text".
    if s.starts_with('[') {
        if let Some(close) = s.find(']') {
            let inner = &s[1..close];
            if !inner.is_empty() {
                s = inner;
            }
        }
    }

    // Strip scheme.
    let s = s
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // Strip path/query/fragment and any trailing punctuation markdown left behind.
    let s = s
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == ')' || c == '(' || c.is_whitespace());

    // Strip a trailing :port if someone embedded one in the scope entry itself.
    let s = s.split(':').next().unwrap_or(s);

    // Wildcard scope entries -> scan the base domain.
    let s = s.strip_prefix("*.").unwrap_or(s);

    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parses a port spec like "80,443,8080" or "1-65535" or "22,80,1000-2000".
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a
                .trim()
                .parse()
                .map_err(|_| format!("invalid port range '{}'", part))?;
            let end: u16 = b
                .trim()
                .parse()
                .map_err(|_| format!("invalid port range '{}'", part))?;
            if start > end {
                return Err(format!("invalid port range '{}' (start > end)", part));
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| format!("invalid port '{}'", part))?;
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("empty port list".to_string());
    }
    Ok(ports)
}

/// Expands "a.b.c.d/prefix" into every address in the block (inclusive of
/// network/broadcast, matching masscan/zmap's default CIDR behaviour).
pub fn expand_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (base, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR '{}': missing prefix", cidr))?;
    let base: Ipv4Addr = base
        .parse()
        .map_err(|_| format!("invalid CIDR '{}': bad base address", cidr))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| format!("invalid CIDR '{}': bad prefix", cidr))?;
    if prefix > 32 {
        return Err(format!("invalid CIDR '{}': prefix must be 0-32", cidr));
    }
    let host_bits = 32 - prefix;
    let count: u64 = 1u64 << host_bits;
    const SAFETY_CAP: u64 = 2_000_000;
    if count > SAFETY_CAP {
        return Err(format!(
            "CIDR '{}' expands to {} addresses, which exceeds the safety cap of {}. \
             Split it into smaller ranges.",
            cidr, count, SAFETY_CAP
        ));
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = u32::from(base) & mask;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        out.push(Ipv4Addr::from(network | (i as u32)));
    }
    Ok(out)
}

/// Bare whitespace/comment/blank-line cleanup for a line from a -cidr file.
/// Deliberately NOT the same as clean_line(): clean_line splits on '/' to
/// strip URL paths, which would mangle "192.168.0.0/24" into just
/// "192.168.0.0" - CIDR notation needs its own, much simpler cleaner.
fn clean_cidr_line(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('#') {
        None
    } else {
        Some(s.to_string())
    }
}

/// Resolves the -cidr argument: if it names an existing file, every
/// non-empty/non-comment line in it is expanded as its own CIDR and the
/// results concatenated (so a -cidr file can list many ranges, one per
/// line). Otherwise the argument itself is treated as a single literal
/// CIDR, e.g. "-cidr 192.168.0.0/24" - exactly like before.
pub fn resolve_cidr_arg(value: &str) -> Result<Vec<Ipv4Addr>, String> {
    if Path::new(value).is_file() {
        let f = std::fs::File::open(value)
            .map_err(|e| format!("cannot open -cidr file '{}': {}", value, e))?;
        let mut all = Vec::new();
        for line in std::io::BufRead::lines(std::io::BufReader::new(f)) {
            let line = line.map_err(|e| format!("error reading -cidr file '{}': {}", value, e))?;
            if let Some(cleaned) = clean_cidr_line(&line) {
                all.extend(expand_cidr(&cleaned)?);
            }
        }
        Ok(all)
    } else {
        expand_cidr(value)
    }
}

/// Resolves a cleaned host string to zero or more IPv4 addresses.
/// If the string is already a literal IPv4 address, returns it directly
/// without touching the network.
fn resolve_one(host: &str) -> Vec<Ipv4Addr> {
    if let Ok(ip) = Ipv4Addr::from_str(host) {
        return vec![ip];
    }
    // (host, 0) lets std do a plain A/AAAA lookup via getaddrinfo without
    // needing a real port.
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs
            .filter_map(|sa| match sa.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                std::net::IpAddr::V6(_) => None, // IPv4-only in this version
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolves many host strings concurrently (DNS is I/O-bound, so we use far
/// more OS threads than CPU cores to hide lookup latency). Returns the
/// resolved targets plus a reverse IP -> target-index map, and the list of
/// unique IPs actually worth probing on the wire.
pub fn resolve_all(
    hosts: Vec<String>,
    resolver_threads: usize,
) -> (Vec<Target>, HashMap<Ipv4Addr, Vec<usize>>, Vec<Ipv4Addr>) {
    let targets: Arc<Mutex<Vec<Target>>> = Arc::new(Mutex::new(Vec::with_capacity(hosts.len())));
    let hosts = Arc::new(hosts);
    let n = resolver_threads.max(1).min(hosts.len().max(1));

    let mut handles = Vec::with_capacity(n);
    for shard in 0..n {
        let hosts = Arc::clone(&hosts);
        let targets = Arc::clone(&targets);
        handles.push(thread::spawn(move || {
            let mut local = Vec::new();
            let mut i = shard;
            while i < hosts.len() {
                let h = &hosts[i];
                for ip in resolve_one(h) {
                    local.push(Target {
                        display: h.clone(),
                        ip,
                    });
                }
                i += n;
            }
            targets.lock().unwrap().extend(local);
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let targets = Arc::try_unwrap(targets).unwrap().into_inner().unwrap();

    let mut ip_to_targets: HashMap<Ipv4Addr, Vec<usize>> = HashMap::new();
    for (idx, t) in targets.iter().enumerate() {
        ip_to_targets.entry(t.ip).or_default().push(idx);
    }
    let unique_ips: Vec<Ipv4Addr> = ip_to_targets.keys().copied().collect();

    (targets, ip_to_targets, unique_ips)
}

/// Adds raw IPv4 literals (e.g. from -cidr expansion) as their own targets,
/// where the display string is just the IP itself.
pub fn ips_as_targets(ips: Vec<Ipv4Addr>) -> Vec<Target> {
    ips.into_iter()
        .map(|ip| Target {
            display: ip.to_string(),
            ip,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_line_variants() {
        assert_eq!(clean_line("example.com").as_deref(), Some("example.com"));
        assert_eq!(
            clean_line("[www.sub.examole.com](https://www.sub.examole.com)").as_deref(),
            Some("www.sub.examole.com")
        );
        assert_eq!(clean_line("192.168.50.5").as_deref(), Some("192.168.50.5"));
        assert_eq!(
            clean_line("https://api.example.com/v1/some/path").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(clean_line("*.wild.example.com").as_deref(), Some("wild.example.com"));
        assert_eq!(clean_line("# comment"), None);
        assert_eq!(clean_line(""), None);
        assert_eq!(clean_line("   "), None);
    }

    #[test]
    fn test_parse_ports() {
        assert_eq!(parse_ports("80,443,8080").unwrap(), vec![80, 443, 8080]);
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
        let mixed = parse_ports("22,80,1000-1003").unwrap();
        assert_eq!(mixed, vec![22, 80, 1000, 1001, 1002, 1003]);
        assert!(parse_ports("").is_err());
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn test_expand_cidr() {
        let ips = expand_cidr("192.168.1.0/30").unwrap();
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 1, 3),
            ]
        );
        assert!(expand_cidr("192.168.1.0/33").is_err());
        assert!(expand_cidr("not-a-cidr").is_err());
    }
}
