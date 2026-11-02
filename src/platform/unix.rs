//! Pieces shared by macOS and Linux.

use super::STOP;
use crate::classify::Prefix;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// Write end, then read end, of a pipe the stop handler writes to, so a
/// sleeping thread can wait on it. -1 until `on_stop_signal`.
static STOP_PIPE: [AtomicI32; 2] = [AtomicI32::new(-1), AtomicI32::new(-1)];

extern "C" fn handle_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
    let fd = STOP_PIPE[0].load(Ordering::SeqCst);
    if fd >= 0 {
        // write(2) is async-signal-safe; a full pipe already wakes the reader.
        unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
    }
}

/// Sleep up to `timeout`, waking early when a stop is requested. Returns
/// whether a stop was requested.
pub fn wait_for_stop(timeout: Duration) -> bool {
    let fd = STOP_PIPE[1].load(Ordering::SeqCst);
    if fd < 0 {
        std::thread::sleep(timeout);
        return STOP.load(Ordering::SeqCst);
    }
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    if !STOP.load(Ordering::SeqCst) {
        unsafe { libc::poll(&mut poll, 1, ms) };
    }
    STOP.load(Ordering::SeqCst)
}

pub(super) fn require_root(what: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(format!("{what} needs root: run it with sudo"))
    }
}

/// Copy an executable into place by writing a new file and renaming it over
/// the old one. Writing into a binary that is running can crash it, and on
/// macOS leaves a stale code signature that gets the next launch killed.
pub(super) fn copy_exe(src: &Path, dest: &Path) -> Result<(), String> {
    if let (Ok(a), Ok(b)) = (std::fs::canonicalize(src), std::fs::canonicalize(dest)) {
        if a == b {
            return Ok(());
        }
    }
    let tmp = dest.with_extension("new");
    let _ = std::fs::remove_file(&tmp);
    std::fs::copy(src, &tmp).map_err(|err| format!("copy {} failed: {err}", src.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|err| err.to_string())?;
    std::fs::rename(&tmp, dest).map_err(|err| format!("replace {} failed: {err}", dest.display()))?;
    Ok(())
}

/// Restrict `path` to root and `group`: a directory to 0750, anything else
/// (the IPC socket) to 0660. Without root, a non-directory gets 0600 and
/// ownership is left alone.
pub fn share_with_group(path: &Path, group: &str) {
    let is_dir = path.is_dir();
    if unsafe { libc::geteuid() } != 0 {
        if !is_dir {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        return;
    }
    let Ok(name) = CString::new(group) else { return };
    let entry = unsafe { libc::getgrnam(name.as_ptr()) };
    let gid = if entry.is_null() { None } else { Some(unsafe { (*entry).gr_gid }) };
    let _ = std::os::unix::fs::chown(path, Some(0), gid);
    let mode = if is_dir { 0o750 } else { 0o660 };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

/// Set the stop flag on SIGINT and SIGTERM, and wake `wait_for_stop`.
pub fn on_stop_signal() {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
        for fd in fds {
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
            }
        }
        STOP_PIPE[1].store(fds[0], Ordering::SeqCst);
        STOP_PIPE[0].store(fds[1], Ordering::SeqCst);
    }
    unsafe {
        libc::signal(libc::SIGINT, handle_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_stop as *const () as libc::sighandler_t);
    }
}

/// Prefixes of addresses configured on this machine.
pub fn local_prefixes() -> Vec<Prefix> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        let iface = unsafe { &*cursor };
        if !iface.ifa_addr.is_null() && !iface.ifa_netmask.is_null() {
            if let (Some(addr), Some(mask)) = (read_ip(iface.ifa_addr), read_ip(iface.ifa_netmask))
            {
                out.push(Prefix {
                    addr,
                    prefix_len: leading_ones(mask),
                });
            }
        }
        cursor = iface.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    out
}

fn read_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family as i32 };
    if family == libc::AF_INET {
        let v4 = unsafe { &*(addr as *const libc::sockaddr_in) };
        let octets = v4.sin_addr.s_addr.to_ne_bytes();
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if family == libc::AF_INET6 {
        let v6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
        let octets = v6.sin6_addr.s6_addr;
        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }
    None
}

fn leading_ones(mask: IpAddr) -> u8 {
    match mask {
        IpAddr::V4(v4) => u32::from(v4).leading_ones() as u8,
        IpAddr::V6(v6) => u128::from(v6).leading_ones() as u8,
    }
}
