//! Linux meter: an eBPF probe (meter/linux/netcheck.bpf.c) counts bytes per
//! socket inside the kernel, and this reads its map once per snapshot. The
//! probe only counts from the moment it attaches, so every socket is `new`.

use super::{Cadence, Meter, Proto, SocketCount};
use libbpf_rs::{Link, MapCore, MapFlags, MapHandle, Object, ObjectBuilder, RingBufferBuilder};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static PROBE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/netcheck.bpf.o"));

/// Executable paths by (tgid, process start in ns since boot).
type Paths = Arc<Mutex<HashMap<(u32, u64), String>>>;

pub struct EbpfMeter {
    // Dropped in this order: detach first, then close the maps and object.
    links: Vec<Link>,
    flows: MapHandle,
    paths: Paths,
    /// Counters as last reported, to skip unchanged sockets.
    reported: HashMap<u64, (u64, u64)>,
    interval: Duration,
    next_at: Instant,
    /// Unix time minus monotonic time, in ns, to date process starts.
    boot_offset_ns: i128,
    /// The daemon runs in a nested PID namespace (a container), so PIDs come
    /// from the probe's per-namespace field, not the kernel's global one.
    nested: bool,
    watcher_stop: Arc<AtomicBool>,
    _object: Object,
}

impl EbpfMeter {
    pub fn open() -> Result<Self, String> {
        let mut open = ObjectBuilder::default()
            .open_memory(PROBE)
            .map_err(|err| format!("opening the eBPF probe failed: {err}"))?;
        // A kernel without IPv6 or with renamed functions loses those hooks only.
        let available = kernel_functions();
        let pidns = own_pid_namespace();
        if let Some((dev, ino)) = pidns {
            let rodata = open
                .maps_mut()
                .find(|map| map.name().to_string_lossy().ends_with(".rodata"))
                .ok_or("the eBPF probe has no .rodata section")?;
            let mut rodata = rodata;
            let bytes = rodata.initial_value_mut().ok_or("the eBPF probe's .rodata is empty")?;
            bytes[0..8].copy_from_slice(&dev.to_ne_bytes());
            bytes[8..16].copy_from_slice(&ino.to_ne_bytes());
        }
        let mut skipped = Vec::new();
        for mut prog in open.progs_mut() {
            let section = prog.section().to_string_lossy().into_owned();
            let target = section.rsplit('/').next().unwrap_or_default().to_string();
            if !available.contains(&target) {
                prog.set_autoload(false);
                skipped.push(prog.name().to_string_lossy().into_owned());
                eprintln!("meter: {target} is not in this kernel; that hook is off");
            }
        }
        let object = open
            .load()
            .map_err(|err| format!("loading the eBPF probe failed (it needs root): {err}"))?;
        let mut links = Vec::new();
        for prog in object.progs_mut() {
            if skipped.iter().any(|name| prog.name() == name.as_str()) {
                continue;
            }
            let link = prog
                .attach()
                .map_err(|err| format!("attaching {} failed: {err}", prog.name().to_string_lossy()))?;
            links.push(link);
        }
        let handle = |name: &str| -> Result<MapHandle, String> {
            let map = object
                .maps()
                .find(|map| map.name() == name)
                .ok_or_else(|| format!("the eBPF probe has no {name} map"))?;
            MapHandle::try_from(&map).map_err(|err| format!("opening the {name} map failed: {err}"))
        };
        let flows = handle("flows")?;
        let processes = handle("processes")?;

        let paths: Paths = Arc::default();
        let watcher_stop = Arc::new(AtomicBool::new(false));
        let nested = pidns.is_some();
        watch_processes(processes, Arc::clone(&paths), Arc::clone(&watcher_stop), nested);

        Ok(Self {
            links,
            flows,
            paths,
            reported: HashMap::new(),
            interval: Duration::from_secs(10),
            // The first snapshot comes after 1 s, as the contract asks.
            next_at: Instant::now() + Duration::from_secs(1),
            boot_offset_ns: unix_ns() - monotonic_ns(),
            nested,
            watcher_stop,
            _object: object,
        })
    }

    fn read(&mut self) -> Result<Vec<SocketCount>, String> {
        let mut out = Vec::new();
        let mut present = HashSet::new();
        let mut closed = Vec::new();
        let entries = self
            .flows
            .lookup_batch(512, MapFlags::ANY, MapFlags::ANY)
            .map_err(|err| format!("reading the flows map failed: {err}"))?;
        for (key, value) in entries {
            let (Ok(key), Some(flow)) = (<[u8; 8]>::try_from(key.as_slice()), Flow::parse(&value)) else {
                continue;
            };
            let cookie = u64::from_ne_bytes(key);
            present.insert(cookie);
            let unchanged = self.reported.get(&cookie) == Some(&(flow.rx, flow.tx));
            if unchanged && !flow.closed {
                continue;
            }
            self.reported.insert(cookie, (flow.rx, flow.tx));
            if flow.closed {
                closed.push(cookie);
            }
            out.push(self.socket(cookie, &flow));
        }
        // A closed socket sees no more traffic, so its entry can go once reported.
        for cookie in &closed {
            let _ = self.flows.delete(&cookie.to_ne_bytes());
            self.reported.remove(cookie);
        }
        // Entries the kernel evicted from the LRU map.
        self.reported.retain(|cookie, _| present.contains(cookie));
        Ok(out)
    }

    fn socket(&self, cookie: u64, flow: &Flow) -> SocketCount {
        let start_unix = (self.boot_offset_ns + flow.start_ns as i128) / 1_000_000_000;
        let pid = flow.local_pid(self.nested);
        SocketCount {
            source: cookie,
            new: true,
            closed: flow.closed,
            pid,
            start_time: start_unix.max(0) as u64,
            proto: if flow.proto == 2 { Proto::Udp } else { Proto::Tcp },
            name: flow.comm.clone(),
            local: flow.local(),
            remote: flow.remote(),
            rx: flow.rx,
            tx: flow.tx,
            path: self.path(flow.tgid, pid, flow.start_ns),
            ..SocketCount::default()
        }
    }

    /// Cached by global PID; read from /proc by the PID this namespace sees
    /// (0 when the process lives outside it, so no path).
    fn path(&self, tgid: u32, local_pid: u32, start_ns: u64) -> Option<String> {
        let mut paths = self.paths.lock().ok()?;
        if let Some(path) = paths.get(&(tgid, start_ns)) {
            return Some(path.clone());
        }
        let path = exe_path(local_pid)?;
        paths.insert((tgid, start_ns), path.clone());
        Some(path)
    }
}

impl Meter for EbpfMeter {
    fn backend(&self) -> &'static str {
        "ebpf"
    }

    fn next_sample(&mut self) -> Result<Vec<SocketCount>, String> {
        // Wakes at once on SIGTERM, so a stop never waits out the interval.
        crate::platform::wait_for_stop(self.next_at.saturating_duration_since(Instant::now()));
        self.next_at = Instant::now() + self.interval;
        self.read()
    }

    fn set_cadence(&mut self, cadence: Cadence) -> Result<(), String> {
        self.interval = match cadence {
            Cadence::Idle => Duration::from_secs(10),
            Cadence::Live => Duration::from_secs(1),
        };
        self.next_at = self.next_at.min(Instant::now() + self.interval);
        Ok(())
    }

    fn snapshot_now(&mut self) -> Result<Vec<SocketCount>, String> {
        self.read()
    }
}

impl Drop for EbpfMeter {
    fn drop(&mut self) {
        self.watcher_stop.store(true, Ordering::Relaxed);
        self.links.clear();
    }
}

/// `struct flow` from the probe.
struct Flow {
    rx: u64,
    tx: u64,
    start_ns: u64,
    tgid: u32,
    family: u16,
    proto: u8,
    closed: bool,
    lport: u16,
    rport: u16,
    laddr: [u8; 16],
    raddr: [u8; 16],
    comm: String,
    ns_tgid: u32,
}

impl Flow {
    const SIZE: usize = 88;

    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let u64_at = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
        let u16_at = |at: usize| u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap());
        let comm = &bytes[68..84];
        let len = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
        Some(Self {
            rx: u64_at(0),
            tx: u64_at(8),
            start_ns: u64_at(16),
            tgid: u32::from_ne_bytes(bytes[24..28].try_into().unwrap()),
            family: u16_at(28),
            proto: bytes[30],
            closed: bytes[31] != 0,
            lport: u16_at(32),
            rport: u16_at(34),
            laddr: bytes[36..52].try_into().unwrap(),
            raddr: bytes[52..68].try_into().unwrap(),
            comm: String::from_utf8_lossy(&comm[..len]).into_owned(),
            ns_tgid: u32::from_ne_bytes(bytes[84..88].try_into().unwrap()),
        })
    }

    fn local_pid(&self, nested: bool) -> u32 {
        if nested {
            self.ns_tgid
        } else {
            self.tgid
        }
    }

    fn ip(&self, raw: &[u8; 16]) -> Option<IpAddr> {
        match self.family {
            2 => Some(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
            // Dual-stack sockets carry IPv4 peers as ::ffff:a.b.c.d.
            10 => Some(Ipv6Addr::from(*raw).to_canonical()),
            _ => None,
        }
    }

    fn local(&self) -> Option<SocketAddr> {
        self.ip(&self.laddr).map(|ip| SocketAddr::new(ip, self.lport))
    }

    fn remote(&self) -> Option<SocketAddr> {
        let ip = self.ip(&self.raddr)?;
        if self.rport == 0 || ip.is_unspecified() {
            return None;
        }
        Some(SocketAddr::new(ip, self.rport))
    }
}

/// Read each new process's path as soon as the probe reports it, while the
/// process still exists. Short-lived processes would be gone by the next snapshot.
fn watch_processes(processes: MapHandle, paths: Paths, stop: Arc<AtomicBool>, nested: bool) {
    std::thread::spawn(move || {
        let mut builder = RingBufferBuilder::new();
        let seen = Arc::clone(&paths);
        let added = builder.add(&processes, move |data: &[u8]| {
            if data.len() >= 16 {
                let start_ns = u64::from_ne_bytes(data[0..8].try_into().unwrap());
                let tgid = u32::from_ne_bytes(data[8..12].try_into().unwrap());
                let ns_tgid = u32::from_ne_bytes(data[12..16].try_into().unwrap());
                let local = if nested { ns_tgid } else { tgid };
                if let (Some(path), Ok(mut paths)) = (exe_path(local), seen.lock()) {
                    if paths.len() > 4096 {
                        paths.clear();
                    }
                    paths.insert((tgid, start_ns), path);
                }
            }
            0
        });
        let ring = match added {
            Ok(_) => builder.build(),
            Err(err) => Err(err),
        };
        let Ok(ring) = ring else {
            eprintln!("meter: process watcher failed to start; short-lived processes may lack a path");
            return;
        };
        // A long timeout keeps idle wakeups rare; stopping waits at most this long.
        while !stop.load(Ordering::Relaxed) {
            if ring.poll(Duration::from_secs(30)).is_err() {
                break;
            }
        }
    });
}

fn exe_path(tgid: u32) -> Option<String> {
    if tgid == 0 {
        return None;
    }
    let path = std::fs::read_link(format!("/proc/{tgid}/exe")).ok()?;
    let path = path.to_str()?;
    Some(path.strip_suffix(" (deleted)").unwrap_or(path).to_string())
}

/// The daemon's PID namespace as (dev, ino), or `None` in the root namespace.
fn own_pid_namespace() -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    // The root PID namespace always has this inode (PROC_PID_INIT_INO).
    const ROOT: u64 = 0xEFFF_FFFC;
    let meta = std::fs::metadata("/proc/self/ns/pid").ok()?;
    (meta.ino() != ROOT).then(|| (meta.dev(), meta.ino()))
}

/// Function names in the running kernel, from /proc/kallsyms.
fn kernel_functions() -> HashSet<String> {
    let text = std::fs::read_to_string("/proc/kallsyms").unwrap_or_default();
    text.lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(|name| name.to_string())
        .collect()
}

fn monotonic_ns() -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

fn unix_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_bytes() -> Vec<u8> {
        let mut b = vec![0u8; Flow::SIZE];
        b[0..8].copy_from_slice(&1_000u64.to_ne_bytes());
        b[8..16].copy_from_slice(&200u64.to_ne_bytes());
        b[16..24].copy_from_slice(&5_000_000_000u64.to_ne_bytes());
        b[24..28].copy_from_slice(&4242u32.to_ne_bytes());
        b[28..30].copy_from_slice(&10u16.to_ne_bytes());
        b[30] = 1;
        b[31] = 1;
        b[32..34].copy_from_slice(&50_000u16.to_ne_bytes());
        b[34..36].copy_from_slice(&443u16.to_ne_bytes());
        // ::1 locally, ::ffff:1.1.1.1 remotely.
        b[51] = 1;
        b[62] = 0xff;
        b[63] = 0xff;
        b[64..68].copy_from_slice(&[1, 1, 1, 1]);
        b[68..72].copy_from_slice(b"curl");
        b[84..88].copy_from_slice(&42u32.to_ne_bytes());
        b
    }

    #[test]
    fn parses_the_probe_flow_layout() {
        let flow = Flow::parse(&flow_bytes()).unwrap();
        assert_eq!((flow.rx, flow.tx, flow.tgid, flow.proto), (1_000, 200, 4242, 1));
        assert!(flow.closed);
        assert_eq!(flow.comm, "curl");
        assert_eq!((flow.local_pid(false), flow.local_pid(true)), (4242, 42));
        assert_eq!(flow.local(), Some("[::1]:50000".parse().unwrap()));
        assert_eq!(flow.remote(), Some("1.1.1.1:443".parse().unwrap()), "v4-mapped peers become IPv4");
    }

    /// Needs root: `sudo <test binary> --ignored probe_counts`.
    #[test]
    #[ignore]
    fn probe_counts_its_own_loopback_transfer() {
        use std::io::{Read, Write};
        let mut meter = EbpfMeter::open().expect("open the meter (needs root)");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).unwrap();
            buf.len()
        });
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.write_all(&vec![7u8; 1_234_567]).unwrap();
        drop(client);
        assert_eq!(server.join().unwrap(), 1_234_567);
        let sockets = meter.snapshot_now().unwrap();
        let me = std::process::id();
        let mine: Vec<_> = sockets.iter().filter(|s| s.pid == me).collect();
        for s in &sockets {
            eprintln!("pid {} name {:?} rx {} tx {} closed {} local {:?} remote {:?} path {:?}", s.pid, s.name, s.rx, s.tx, s.closed, s.local, s.remote, s.path);
        }
        eprintln!("{} sockets in snapshot, {} mine (pid {me})", sockets.len(), mine.len());
        assert!(mine.iter().any(|s| s.tx == 1_234_567 && s.closed), "client socket");
        assert!(mine.iter().any(|s| s.rx == 1_234_567), "server socket");
        assert!(mine.iter().all(|s| s.path.is_some()), "paths resolved");
    }

    #[test]
    fn an_unconnected_socket_has_no_remote() {
        let mut bytes = flow_bytes();
        bytes[34..36].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(Flow::parse(&bytes).unwrap().remote(), None);
        assert!(Flow::parse(&bytes[..40]).is_none());
    }
}
