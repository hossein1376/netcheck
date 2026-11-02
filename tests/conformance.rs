//! Meter conformance: real loopback traffic through a real daemon and meter,
//! checked to the byte. Slow and needs the OS meter, so it is ignored by default:
//!
//!     cargo test --release --test conformance -- --ignored --test-threads=1
//!
//! This test process predates the daemon it starts, like a long-running app.
//! A copy of it started later plays a process that is newer than the daemon.
#![cfg(target_os = "macos")]

use netcheck::{min_hour, By, Store, UsageRow};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

const MB: u64 = 1_000_000;
const CHILD_ENV: &str = "NETCHECK_CONFORMANCE_CHILD";

#[test]
#[ignore]
fn meter_counts_loopback_traffic_exactly() {
    let root = std::env::temp_dir().join(format!("ncconf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("netcheck.db");
    let started = SystemTime::now();

    // Case 2, part one: a connection that is already transferring when the
    // daemon starts. Only what moves after the start may be billed.
    let (more, long_server) = serve_in_two_parts(4 * MB, 2 * MB);
    let mut long_client = TcpStream::connect(long_server.0).unwrap();
    read_exactly(&mut long_client, 4 * MB);

    let mut daemon = spawn_daemon(&db);
    wait_for_first_sample(&db, &mut daemon);

    // Case 1: short connections from a process that predates the daemon.
    let short = serve(3 * MB, 5);
    for _ in 0..5 {
        assert_eq!(fetch(short.0), 3 * MB);
    }
    short.1.join().unwrap();

    // Case 2, part two.
    more.send(()).unwrap();
    read_exactly(&mut long_client, 2 * MB);
    drop(long_client);
    long_server.1.join().unwrap();

    // Cases 3 and 5: a process started after the daemon, gone within a poll.
    let newer = serve(3 * MB, 1);
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["child_client", "--exact", "--ignored", "--test-threads=1", "--quiet"])
        .env(CHILD_ENV, newer.0.to_string())
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "child client failed");
    newer.1.join().unwrap();

    // Case 4: unconnected UDP, counted once.
    let (udp_sent, udp_received) = udp_burst(1000, 1000);

    // Case 6: a second daemon on the same database is refused.
    let second = Command::new(env!("CARGO_BIN_EXE_netcheck"))
        .args(["daemon", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(!second.status.success(), "a second daemon must not start");
    let said = String::from_utf8_lossy(&second.stderr);
    assert!(said.contains("already running"), "second daemon said: {said}");

    // Stop at idle cadence: the daemon must take a final snapshot so the
    // last interval is not lost.
    stop(&mut daemon);

    let store = Store::open_read(&db).unwrap();
    let rows = store.usage(min_hour(started), None, By::Executable).unwrap();
    let me = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let me = me.to_str().unwrap();
    let mine = rows
        .iter()
        .find(|row| row.key == me)
        .unwrap_or_else(|| panic!("no row for {me}: {rows:#?}"));

    let tcp = 5 * 3 * MB + 2 * MB + 3 * MB;
    assert_eq!(rx(mine), tcp + udp_received, "received bytes: {mine:#?}");
    assert_eq!(tx(mine), tcp + udp_sent, "sent bytes: {mine:#?}");
    let stem = Path::new(me).file_name().unwrap().to_str().unwrap();
    let orphans: Vec<&UsageRow> = rows
        .iter()
        .filter(|row| row.key.starts_with("name:") && stem.starts_with(row.name.as_str()))
        .collect();
    assert!(orphans.is_empty(), "a process lost its path: {orphans:#?}");

    let _ = std::fs::remove_dir_all(&root);
}

/// The process started after the daemon. Does nothing unless the main test
/// launched it.
#[test]
#[ignore]
fn child_client() {
    let Ok(addr) = std::env::var(CHILD_ENV) else { return };
    assert_eq!(fetch(addr.parse().unwrap()), 3 * MB);
}

fn rx(row: &UsageRow) -> u64 {
    row.internet_rx + row.local_rx + row.unscoped_rx
}

fn tx(row: &UsageRow) -> u64 {
    row.internet_tx + row.local_tx + row.unscoped_tx
}

fn spawn_daemon(db: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_netcheck"))
        .args(["daemon", "--db"])
        .arg(db)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

/// The status file appears after the first sample. Sockets opened from here on
/// are new to the meter.
fn wait_for_first_sample(db: &Path, daemon: &mut Child) {
    let status: PathBuf = db.with_file_name("status.json");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(code) = daemon.try_wait().unwrap() {
            panic!("daemon exited early: {code}");
        }
        if std::fs::read_to_string(&status).is_ok_and(|text| text.contains("\"up\"")) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon never reported a sample");
}

fn stop(daemon: &mut Child) {
    unsafe { libc::kill(daemon.id() as i32, libc::SIGINT) };
    // The daemon notices at its next snapshot, up to one idle interval.
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if let Some(code) = daemon.try_wait().unwrap() {
            assert!(code.success(), "daemon exited with {code}");
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = daemon.kill();
    panic!("daemon did not stop on SIGINT");
}

/// Accept `count` connections and send each `bytes`, then close it.
fn serve(bytes: u64, count: usize) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            write_bytes(&mut stream, bytes);
        }
    });
    (addr, handle)
}

/// Accept one connection, send `first`, wait for the signal, then send `second`.
fn serve_in_two_parts(first: u64, second: u64) -> (mpsc::Sender<()>, (SocketAddr, JoinHandle<()>)) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (go, wait) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        write_bytes(&mut stream, first);
        wait.recv().unwrap();
        write_bytes(&mut stream, second);
    });
    (go, (addr, handle))
}

fn write_bytes(stream: &mut TcpStream, bytes: u64) {
    let chunk = vec![7u8; 64 * 1024];
    let mut left = bytes;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        stream.write_all(&chunk[..n]).unwrap();
        left -= n as u64;
    }
}

fn fetch(addr: SocketAddr) -> u64 {
    let mut stream = TcpStream::connect(addr).unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap() as u64
}

fn read_exactly(stream: &mut TcpStream, bytes: u64) {
    let mut buf = vec![0u8; bytes as usize];
    stream.read_exact(&mut buf).unwrap();
}

/// Send `count` datagrams of `size` bytes from an unconnected socket. Returns
/// (sent, received); loopback can drop datagrams, so both are counted.
fn udp_burst(count: usize, size: usize) -> (u64, u64) {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let target = receiver.local_addr().unwrap();
    let counter = thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut got = 0u64;
        while let Ok(n) = receiver.recv(&mut buf) {
            got += n as u64;
        }
        got
    });
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let payload = vec![1u8; size];
    let mut sent = 0u64;
    for i in 0..count {
        sent += sender.send_to(&payload, target).unwrap() as u64;
        if i % 50 == 49 {
            thread::sleep(Duration::from_millis(2));
        }
    }
    (sent, counter.join().unwrap())
}
