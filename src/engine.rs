use crate::classify::{classify, Prefix, Scope};
use crate::diff::Diff;
use crate::group::group_of;
use crate::meter::{Links, SocketCount};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Hours since the Unix epoch, UTC.
pub fn hour_index(now: SystemTime) -> i64 {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;
    secs.div_euclid(3600)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Buckets {
    pub internet_rx: u64,
    pub internet_tx: u64,
    pub local_rx: u64,
    pub local_tx: u64,
    pub unscoped_rx: u64,
    pub unscoped_tx: u64,
    /// The same bytes across all scopes, split by link kind.
    pub links: Links,
}

impl Buckets {
    pub(crate) fn merge(&mut self, other: &Buckets) {
        self.internet_rx += other.internet_rx;
        self.internet_tx += other.internet_tx;
        self.local_rx += other.local_rx;
        self.local_tx += other.local_tx;
        self.unscoped_rx += other.unscoped_rx;
        self.unscoped_tx += other.unscoped_tx;
        self.links.add(&other.links);
    }

    fn add(&mut self, scope: Scope, rx: u64, tx: u64, links: &Links) {
        self.links.add(links);
        match scope {
            Scope::Internet => {
                self.internet_rx += rx;
                self.internet_tx += tx;
            }
            Scope::Local => {
                self.local_rx += rx;
                self.local_tx += tx;
            }
            Scope::Unscoped => {
                self.unscoped_rx += rx;
                self.unscoped_tx += tx;
            }
        }
    }
}

/// Bytes a VPN process sent and received for the tunnel. The apps inside the
/// tunnel are counted already, so these stay out of app totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Encap {
    pub rx: u64,
    pub tx: u64,
    /// Which physical links carried the tunnel.
    pub links: Links,
}

impl Encap {
    pub(crate) fn merge(&mut self, other: &Encap) {
        self.rx += other.rx;
        self.tx += other.tx;
        self.links.add(&other.links);
    }

    pub fn is_empty(&self) -> bool {
        self.rx == 0 && self.tx == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDelta {
    pub app_key: String,
    pub display_name: String,
    /// The app this executable belongs to. See [`group_of`].
    pub group_key: String,
    pub group_name: String,
    pub hour: i64,
    pub buckets: Buckets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub sockets: Vec<SocketCount>,
}

#[derive(Debug)]
pub struct Engine {
    diff: Diff,
    exclude: HashSet<String>,
}

impl Engine {
    pub fn new(exclude: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            diff: Diff::new(),
            exclude: exclude
                .into_iter()
                .map(|s| s.as_ref().to_ascii_lowercase())
                .collect(),
        }
    }

    /// Forget all flows. Call when a new meter run starts, since source ids restart.
    pub fn reset_flows(&mut self) {
        self.diff = Diff::new();
    }

    /// Fold one cumulative sample into per-app hour buckets.
    pub fn ingest(
        &mut self,
        sample: &Sample,
        now: SystemTime,
        prefixes: &[Prefix],
    ) -> (Vec<AppDelta>, Encap) {
        let hour = hour_index(now);
        let mut by_app: HashMap<(String, String), Buckets> = HashMap::new();
        let mut encap = Encap::default();
        for sock in &sample.sockets {
            let delta = self.diff.observe(sock);
            if sock.closed {
                self.diff.forget(&Diff::key_of(sock));
            }
            if delta.fresh || (delta.rx == 0 && delta.tx == 0) {
                continue;
            }
            // Tunnel daemons are recognised by the process that owns the socket.
            let (real_key, real_name) = process_identity(sock.path.as_deref(), &sock.name);
            if is_excluded(&self.exclude, &sock.name)
                || is_excluded(&self.exclude, &real_name)
                || is_excluded(&self.exclude, file_name(&real_key))
            {
                encap.merge(&Encap {
                    rx: delta.rx,
                    tx: delta.tx,
                    links: delta.links,
                });
                continue;
            }
            let (app_key, display) = app_identity(sock);
            let scope = classify(local_port(sock), remote_ip(sock), prefixes);
            by_app
                .entry((app_key, display))
                .or_default()
                .add(scope, delta.rx, delta.tx, &delta.links);
        }

        let apps = by_app
            .into_iter()
            .map(|((app_key, display_name), buckets)| {
                let (group_key, group_name) = group_of(&app_key, &display_name);
                AppDelta {
                    app_key,
                    display_name,
                    group_key,
                    group_name,
                    hour,
                    buckets,
                }
            })
            .collect();
        (apps, encap)
    }
}

pub fn default_exclude() -> &'static [&'static str] {
    &[
        "mullvad-daemon",
        "mullvad vpn",
        "openvpn",
        "wireguard-go",
        "wireguard",
        "wg",
        "kvpncsvc",
    ]
}

/// Who the bytes are for: the effective process when the socket works on
/// another's behalf and its path is known, otherwise the owning process.
fn app_identity(sock: &SocketCount) -> (String, String) {
    if sock.effective_pid != 0 {
        if let Some(path) = &sock.effective_path {
            return (path.clone(), file_name(path).to_string());
        }
    }
    process_identity(sock.path.as_deref(), &sock.name)
}

/// The executable path when known. Otherwise the process name, so short-lived
/// processes that exited before the meter saw them still group together.
fn process_identity(path: Option<&str>, name: &str) -> (String, String) {
    if let Some(path) = path {
        return (path.to_string(), file_name(path).to_string());
    }
    if name.is_empty() {
        return ("name:unknown".into(), "unknown".into());
    }
    (format!("name:{name}"), name.to_string())
}

pub(crate) fn file_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}

fn remote_ip(sock: &SocketCount) -> Option<IpAddr> {
    sock.remote.map(|addr| addr.ip())
}

fn local_port(sock: &SocketCount) -> Option<u16> {
    sock.local.map(|addr| addr.port()).filter(|port| *port != 0)
}

fn is_excluded(exclude: &HashSet<String>, name: &str) -> bool {
    exclude.contains(&name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::Proto;

    fn at(secs: u64) -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn curl(rx: u64, remote: &str) -> SocketCount {
        SocketCount {
            source: 1,
            new: false,
            closed: false,
            pid: 9,
            start_time: 5,
            proto: Proto::Tcp,
            name: "curl".into(),
            local: Some("10.0.0.8:50000".parse().unwrap()),
            remote: Some(remote.parse().unwrap()),
            rx,
            tx: 10,
            path: Some("/usr/bin/curl".into()),
            ..SocketCount::default()
        }
    }

    #[test]
    fn second_sample_bills_only_the_increase_as_internet() {
        let mut engine = Engine::new(default_exclude());
        let now = at(3_600 * 10 + 10);
        engine.ingest(
            &Sample { sockets: vec![curl(1_000, "1.1.1.1:443")] },
            now,
            &[],
        );
        let (apps, encap) = engine.ingest(
            &Sample { sockets: vec![curl(6_000, "1.1.1.1:443")] },
            now,
            &[],
        );
        assert_eq!(encap.rx, 0);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].app_key, "/usr/bin/curl");
        assert_eq!(apps[0].display_name, "curl");
        assert_eq!(apps[0].buckets.internet_rx, 5_000);
        assert_eq!(apps[0].buckets.local_rx, 0);
    }

    #[test]
    fn tunnel_process_goes_to_encapsulation() {
        let mut engine = Engine::new(default_exclude());
        let now = at(100);
        let mut sock = curl(100, "1.1.1.1:443");
        sock.name = "mullvad-daemon".into();
        sock.path = Some("/usr/local/bin/mullvad-daemon".into());
        engine.ingest(
            &Sample { sockets: vec![sock.clone()] },
            now,
            &[],
        );
        sock.rx = 9_100;
        let (apps, encap) = engine.ingest(
            &Sample { sockets: vec![sock] },
            now,
            &[],
        );
        assert!(apps.is_empty());
        assert_eq!(encap.rx, 9_000);
        assert_eq!(encap.tx, 0);
    }

    #[test]
    fn a_socket_opened_after_the_meter_counts_its_first_sample() {
        let mut engine = Engine::new(default_exclude());
        let now = at(100);
        let mut born = curl(1_000_000, "1.1.1.1:443");
        born.source = 99;
        born.new = true;
        let (apps, _) = engine.ingest(
            &Sample { sockets: vec![born.clone()] },
            now,
            &[],
        );
        assert_eq!(apps[0].buckets.internet_rx, 1_000_000);
        born.rx = 1_050_000;
        let (apps, _) = engine.ingest(
            &Sample { sockets: vec![born] },
            now,
            &[],
        );
        assert_eq!(apps[0].buckets.internet_rx, 50_000);
    }

    #[test]
    fn an_unresolved_process_groups_by_name() {
        let mut engine = Engine::new(default_exclude());
        let now = at(100);
        let mut socks = Vec::new();
        for (source, pid) in [(1, 500), (2, 501)] {
            let mut sock = curl(2_000, "1.1.1.1:443");
            sock.source = source;
            sock.pid = pid;
            sock.new = true;
            sock.path = None;
            socks.push(sock);
        }
        let (apps, _) = engine.ingest(&Sample { sockets: socks }, now, &[]);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].app_key, "name:curl");
        assert_eq!(apps[0].display_name, "curl");
        assert_eq!(apps[0].buckets.internet_rx, 4_000);
    }

    #[test]
    fn reset_flows_baselines_the_next_run() {
        let mut engine = Engine::new(default_exclude());
        let now = at(100);
        engine.ingest(&Sample { sockets: vec![curl(1_000, "1.1.1.1:443")] }, now, &[]);
        engine.reset_flows();
        let (apps, _) =
            engine.ingest(&Sample { sockets: vec![curl(9_000, "1.1.1.1:443")] }, now, &[]);
        assert!(apps.is_empty(), "a reused source id must not bill across runs");
    }

    #[test]
    fn delegated_traffic_counts_for_the_effective_app() {
        let mut engine = Engine::new(default_exclude());
        let mut sock = curl(5_000, "1.1.1.1:443");
        sock.new = true;
        sock.name = "com.apple.WebKit.Networking".into();
        sock.path = Some("/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking".into());
        sock.effective_pid = 77;
        sock.effective_path = Some("/Applications/Safari.app/Contents/MacOS/Safari".into());
        sock.links = Links { wifi_rx: 5_000, wifi_tx: 10, ..Links::default() };
        let (apps, _) = engine.ingest(&Sample { sockets: vec![sock] }, at(100), &[]);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].group_name, "Safari");
        assert_eq!(apps[0].buckets.internet_rx, 5_000);
        assert_eq!(apps[0].buckets.links.wifi_rx, 5_000);
    }

    #[test]
    fn a_tunnel_keeps_its_link_split_out_of_app_totals() {
        let mut engine = Engine::new(default_exclude());
        let mut tunnel = curl(8_000, "185.65.135.1:51820");
        tunnel.new = true;
        tunnel.name = "mullvad-daemon".into();
        tunnel.path = Some("/Applications/Mullvad VPN.app/Contents/Resources/mullvad-daemon".into());
        tunnel.links = Links { wifi_rx: 8_000, wifi_tx: 10, ..Links::default() };
        let (apps, encap) = engine.ingest(&Sample { sockets: vec![tunnel] }, at(100), &[]);
        assert!(apps.is_empty());
        assert_eq!(encap.links.wifi_rx, 8_000);
    }

    #[test]
    fn lan_peer_is_local() {
        let mut engine = Engine::new(default_exclude());
        let now = at(100);
        engine.ingest(
            &Sample { sockets: vec![curl(10, "192.168.1.20:80")] },
            now,
            &[],
        );
        let mut sock = curl(410, "192.168.1.20:80");
        sock.tx = 10;
        let (apps, _) = engine.ingest(
            &Sample { sockets: vec![sock] },
            now,
            &[],
        );
        assert_eq!(apps[0].buckets.local_rx, 400);
        assert_eq!(apps[0].buckets.internet_rx, 0);
    }
}
