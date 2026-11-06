# duelscan

**v1.0** — @hacktivist1337

A high-throughput port scanner written in Rust. Uses masscan/zmap-style
stateless SYN scanning when run as root (or with `CAP_NET_RAW`), and falls
back to an async TCP connect-scan otherwise.

## How it works

Instead of tracking state per probe, the SYN sequence number is a keyed
hash of (target IP, target port, source port). When a SYN-ACK arrives, the
same hash is recomputed and checked against the response — a match confirms
it's a reply to a probe we actually sent, without storing anything
per-probe. This stateless design (the same one masscan and zmap use) is
what allows scanning at line rate with no connection-table overhead.

Root is required for the SYN path because opening a raw socket needs
`CAP_NET_RAW` — the same reason masscan, zmap, and `nmap -sS` all need
root. Without it, duelscan automatically falls back to a connect-scan (the
approach rustscan's default mode uses), which needs no special privileges.

## Install

```bash
cargo build --release --locked
# binary: target/release/duelscan
```

Fast path (SYN scan) needs root or `CAP_NET_RAW`:
```bash
sudo ./target/release/duelscan -list scope.txt -ports 1-65535
# or grant the capability directly:
sudo setcap cap_net_raw+ep ./target/release/duelscan
```

## Usage

```
duelscan [-list targets.txt] -ports <spec> [options]
cat targets.txt | duelscan -ports <spec> [options]
```

| Flag                | Description                                                        |
|---------------------|----------------------------------------------------------------------|
| `-list`             | Target file, or a single host/IP.                                   |
| `-ports`            | `80,443,8080` or `1-65535` or mixed (default: `1-1000`).            |
| `-cidr`             | CIDR range, or a file with one CIDR per line.                       |
| `-silent`           | Only print result lines, no banner/stats.                           |
| `-o`                | Also write results to a file.                                       |
| `-threads`          | Parallelism — default: 4 (SYN mode) / 4000 (connect-scan).          |
| `-rate`             | SYN packets/sec cap (default: 2000).                                |
| `-timeout`          | Response/grace timeout, ms (default: 1500).                         |
| `-retry`            | Retries on a local send/connect error (default: 0).                 |
| `-ulimit`           | Raise the open-fd limit, rustscan-style.                            |
| `-decoy`            | Detect targets faking "every port open".                            |
| `-decoy-threshold`  | Open-port count that triggers it (default: 50).                     |
| `-decoy-rate`       | Rescan rate for flagged targets (default: 1000).                    |

If `-list` is omitted, targets are read from stdin when piped (it won't
block waiting on an interactive terminal).

## Target input

`-list` and `-cidr` each accept either a literal value or a file path:
```
-list hackerone.com     # single target
-list targets.txt       # one target per line
-cidr 192.168.0.0/24    # single range
-cidr ranges.txt        # one CIDR per line
```

List lines are cleaned automatically — markdown links, `http(s)://`
prefixes, paths, and `*.` wildcards are stripped down to a bare host/IP:
```
example.com
[www.sub.example.com](https://www.sub.example.com)
192.168.50.5
https://api.example.com/v1/path
*.wild.example.com
```

## Output

```
example.com:80
192.0.2.10:8080
```

Results are deduplicated and sorted per target: if a hostname resolves to
multiple IPs, a port found open on more than one of them is only printed
once, and a target's own ports always print in ascending order. Each
target is printed as soon as it's done, independent of the rest of the
list — results stream in as the scan progresses rather than all arriving
at the end.

## Threads, rate, retry

`-rate` is the main speed/safety knob. Sending faster than your NIC/driver
can drain fills the send queue and the kernel starts rejecting sends —
those probes are lost unless `-retry` is also set, so an unrealistic rate
can silently lose coverage. Watch the "errored" count in the summary line;
it should be 0.

`-threads` controls parallelism, but its useful range is narrow compared
to `-rate` — past a point, more threads mostly adds overhead without
speeding anything up. The defaults are a reasonable starting point for
most scans.

`-retry` only covers local send/connect errors (e.g. a transient ENOBUFS)
— not closed ports or timeouts, which are real answers, not failures.

## -ulimit

Connect-scan mode uses one file descriptor per in-flight probe.
`-ulimit <n>` raises `RLIMIT_NOFILE` to `<n>` (rustscan's `--ulimit` does
the same thing). Without it, concurrency is automatically capped to
whatever the current limit allows, so results stay accurate either way —
the flag just lets you go higher.

## -decoy

Some targets (WAFs, IDS/IPS, portspoof-style defenses) respond to every
probed port with a fake SYN-ACK once they notice a scan — indistinguishable
from a genuinely wide-open host until the scan finishes. `-decoy` watches
each target's open-port count live; once it reaches `-decoy-threshold`
(default 50), that target is aborted immediately and requeued.

Requeued targets are rescanned at `-decoy-rate` (default 1000, separate
from `-rate`). If a target passes this time, its results are reported
normally. If it's still above the threshold, it's reported as `FAILED`
and its name (only) is written to `failed_ports.txt` for manual follow-up
at an even lower rate.

## Limitations

- IPv4 + TCP only; no UDP scanning in this version.
- Hasn't been benchmarked against live internet targets from the build
  environment used to develop it (network access there is restricted to
  package registries) — logic was verified end-to-end against real local
  TCP listeners instead.
- The local kernel may send its own RST in response to an unsolicited
  SYN-ACK, since it doesn't know about the raw-socket SYN duelscan sent
  (masscan/zmap have the same situation). Doesn't affect accuracy — the
  SYN-ACK is already captured — but for a fully clean handshake on the
  wire: `iptables -A OUTPUT -p tcp --sport 61337 --tcp-flags RST RST -j DROP`
- Source IP for checksums is computed once per scan, assuming a single
  outbound route/interface.
