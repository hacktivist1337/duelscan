use std::env;
use std::process::exit;

/// Program configuration, parsed from argv.
/// Flags are matched with either one or two leading dashes ("-ports" or "--ports")
/// to match the exact spec (masscan/rustscan-style single-dash flags).
#[derive(Debug, Clone)]
pub struct Config {
    pub list: Option<String>,
    pub ports: String,
    pub silent: bool,
    pub output: Option<String>,
    pub cidr: Option<String>,
    // Extras, not in the original spec but explicitly allowed ("parallelism/thread
    // commands are up to you"):
    //
    // `threads` is intentionally Option<usize>: SYN-mode TX threads and
    // connect-scan concurrency live on completely different sane scales (a
    // handful vs. thousands), so "not specified" has to mean something
    // different per engine. See main.rs for how each engine resolves None.
    pub threads: Option<usize>,
    pub rate_pps: u64,   // SYN packets/sec cap; 0 = uncapped (not recommended, see -rate help)
    pub timeout_ms: u64, // connect-scan timeout, and SYN grace period base
    pub ulimit: Option<u64>, // explicit request to raise RLIMIT_NOFILE, rustscan-style
    pub retry: u32,      // extra attempts on a genuine local send/connect error; 0 = no retry

    // Decoy/deception detection - OFF unless -decoy is explicitly given, in
    // which case -decoy-threshold and -decoy-rate shape how it behaves. See
    // decoy.rs and README for the two-pass mechanism.
    pub decoy: bool,
    pub decoy_threshold: u32,
    pub decoy_rate: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            list: None,
            ports: "1-1000".to_string(),
            silent: false,
            output: None,
            cidr: None,
            threads: None,
            rate_pps: 2000,
            timeout_ms: 1500,
            ulimit: None,
            retry: 0,
            decoy: false,
            decoy_threshold: 50,
            decoy_rate: 1000,
        }
    }
}

fn strip_dashes(arg: &str) -> &str {
    arg.trim_start_matches('-')
}

pub fn parse_args() -> Config {
    let mut cfg = Config::default();
    let args: Vec<String> = env::args().collect();
    let mut i = 1;

    fn need_value(flag: &str, args: &[String], i: usize) -> String {
        match args.get(i + 1) {
            Some(v) => v.clone(),
            None => {
                eprintln!("error: -{} requires a value", flag);
                exit(2);
            }
        }
    }

    while i < args.len() {
        let raw = &args[i];
        if !raw.starts_with('-') {
            eprintln!("error: unexpected argument '{}'", raw);
            exit(2);
        }
        let flag = strip_dashes(raw);
        match flag {
            "list" | "l" => {
                cfg.list = Some(need_value(flag, &args, i));
                i += 1;
            }
            "ports" | "p" => {
                cfg.ports = need_value(flag, &args, i);
                i += 1;
            }
            "silent" => {
                cfg.silent = true;
            }
            "o" | "output" => {
                cfg.output = Some(need_value(flag, &args, i));
                i += 1;
            }
            "cidr" => {
                cfg.cidr = Some(need_value(flag, &args, i));
                i += 1;
            }
            "threads" | "t" => {
                let v = need_value(flag, &args, i);
                let n: usize = v.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid -threads value '{}'", v);
                    exit(2);
                });
                cfg.threads = Some(n);
                i += 1;
            }
            "rate" => {
                let v = need_value(flag, &args, i);
                cfg.rate_pps = v.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid -rate value '{}'", v);
                    exit(2);
                });
                i += 1;
            }
            "timeout" => {
                let v = need_value(flag, &args, i);
                cfg.timeout_ms = v.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid -timeout value '{}'", v);
                    exit(2);
                });
                i += 1;
            }
            "ulimit" | "u" => {
                let v = need_value(flag, &args, i);
                let n: u64 = v.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid -ulimit value '{}'", v);
                    exit(2);
                });
                cfg.ulimit = Some(n);
                i += 1;
            }
            "retry" => {
                let v = need_value(flag, &args, i);
                let n: u32 = v.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid -retry value '{}'", v);
                    exit(2);
                });
                cfg.retry = n;
                i += 1;
            }
            "decoy" => {
                cfg.decoy = true;
            }
            "decoy-threshold" => {
                let v = need_value(flag, &args, i);
                let n: u32 = v.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid -decoy-threshold value '{}'", v);
                    exit(2);
                });
                cfg.decoy_threshold = n;
                i += 1;
            }
            "decoy-rate" => {
                let v = need_value(flag, &args, i);
                let n: u64 = v.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid -decoy-rate value '{}'", v);
                    exit(2);
                });
                cfg.decoy_rate = n;
                i += 1;
            }
            "h" | "help" => {
                print_help();
                exit(0);
            }
            other => {
                eprintln!("error: unknown flag '-{}'", other);
                print_help();
                exit(2);
            }
        }
        i += 1;
    }

    cfg
}

fn print_help() {
    eprintln!(
        r#"duelscan - high-throughput port scanner

USAGE:
    duelscan [-list targets.txt] -ports <spec> [options]
    cat targets.txt | duelscan -ports <spec> [options]

OPTIONS:
    -list <file|host>     Targets: file, single host/IP, or stdin if omitted.
    -ports <spec>         "80,443,8080" or "1-65535" or mixed.
    -cidr <cidr|file>     CIDR range, or a file with one CIDR per line.
    -silent               Only print result lines, no banner/stats.
    -o <file>             Also write results here.
    -threads <n>          Parallelism (default: 4 SYN mode / 4000 connect-scan).
    -rate <pps>           SYN send rate cap (default: 2000).
    -timeout <ms>         Response/grace timeout, ms (default: 1500).
    -retry <n>            Retries on a local send error (default: 0).
    -ulimit <n>           Raise open-fd limit, rustscan-style.
    -decoy                Detect targets faking "every port open".
    -decoy-threshold <n>  Open-port count that triggers it (default: 50).
    -decoy-rate <pps>     Rescan rate for flagged targets (default: 1000).
    -h, -help             Show this help.

See README.md for details on -decoy and why -threads defaults differ by engine.
"#
    );
}
