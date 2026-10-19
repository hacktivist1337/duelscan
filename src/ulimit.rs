//! RLIMIT_NOFILE (open file descriptor) handling - same role as rustscan's
//! `--ulimit`. Every outbound TCP connect-scan probe consumes one fd for the
//! lifetime of its socket; if the process's open-fd ceiling is lower than the
//! concurrency we're asking for, probes past that ceiling fail to even open a
//! socket. That reads back as "closed", not "couldn't check" - a silent
//! accuracy loss, not just a performance one. (The raw-socket SYN path
//! doesn't have this problem: it uses a small, fixed number of long-lived raw
//! sockets regardless of how many hosts/ports are being probed.)

/// Returns (soft, hard) limits for RLIMIT_NOFILE.
pub fn get_nofile_limits() -> (u64, u64) {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    if rc != 0 {
        // Conservative fallback if the syscall itself fails for some reason.
        return (1024, 1024);
    }
    (lim.rlim_cur as u64, lim.rlim_max as u64)
}

/// Tries to raise RLIMIT_NOFILE to `target`, rustscan-`--ulimit`-style.
///
/// First attempt: ask for *both* soft and hard to become `target` (raised
/// together, like rustscan does). This only succeeds if the caller has
/// CAP_SYS_RESOURCE (root) or `target` is already <= the current hard limit
/// - otherwise the kernel returns EPERM and changes nothing.
///
/// If that's rejected, fall back to raising just the soft limit up to
/// whatever the hard limit already is - the best any unprivileged process
/// can do, and the same ceiling rustscan itself runs into in that case.
///
/// Either way, returns the soft limit actually in effect afterwards, so the
/// caller can report the real number rather than assuming the request was
/// fully honoured.
pub fn raise_nofile_limit(target: u64) -> Result<u64, String> {
    let (_soft, hard_before) = get_nofile_limits();

    let desired_hard = target.max(hard_before);
    let full = libc::rlimit {
        rlim_cur: target,
        rlim_max: desired_hard,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &full) } == 0 {
        return Ok(target);
    }

    // Not privileged enough to raise the hard limit itself - settle for
    // raising soft as far as the existing hard ceiling allows.
    let capped = target.min(hard_before);
    let fallback = libc::rlimit {
        rlim_cur: capped,
        rlim_max: hard_before,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &fallback) } == 0 {
        Ok(capped)
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}
