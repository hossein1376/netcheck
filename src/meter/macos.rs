//! macOS meter: the `nstat_meter` helper reads NetworkStatistics and streams
//! NC02 frames over a pipe.

use super::frame::{read_magic, read_snapshot};
use super::{Cadence, Meter, SocketCount};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub fn meter_path() -> PathBuf {
    if let Some(path) = std::env::var_os("NETCHECK_METER") {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("nstat_meter");
            if beside.exists() {
                return beside;
            }
        }
    }
    PathBuf::from(env!("NETCHECK_METER_DEFAULT"))
}

pub struct NstatMeter {
    child: Child,
    /// Commands: `l` live cadence, `i` idle cadence, `n` snapshot now.
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl NstatMeter {
    pub fn spawn() -> Result<Self, String> {
        let meter = meter_path();
        if !meter.exists() {
            return Err(format!("meter binary is missing at {}", meter.display()));
        }
        let mut child = Command::new(&meter)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("failed to start {}: {err}", meter.display()))?;
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    eprintln!("meter: {line}");
                }
            });
        }
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("meter pipes are missing".into());
        };
        // Wrap now so a bad header still kills the child on drop.
        let mut meter = Self { child, stdin, stdout };
        read_magic(&mut meter.stdout).map_err(|err| err.to_string())?;
        Ok(meter)
    }
}

impl Meter for NstatMeter {
    fn backend(&self) -> &'static str {
        "networkstatistics"
    }

    fn next_sample(&mut self) -> Result<Vec<SocketCount>, String> {
        read_snapshot(&mut self.stdout)
            .map(|snapshot| snapshot.sockets)
            .map_err(|err| err.to_string())
    }

    fn set_cadence(&mut self, cadence: Cadence) -> Result<(), String> {
        let command: &[u8] = match cadence {
            Cadence::Idle => b"i",
            Cadence::Live => b"l",
        };
        self.command(command)
    }

    fn snapshot_now(&mut self) -> Result<Vec<SocketCount>, String> {
        self.command(b"n")?;
        // A timer snapshot may arrive first. Counters are cumulative, so the
        // latest report per socket stands for all of them.
        let mut latest: HashMap<u64, SocketCount> = HashMap::new();
        loop {
            let snapshot = read_snapshot(&mut self.stdout).map_err(|err| err.to_string())?;
            for sock in snapshot.sockets {
                let closed = sock.closed || latest.get(&sock.source).is_some_and(|old| old.closed);
                latest.insert(sock.source, SocketCount { closed, ..sock });
            }
            if snapshot.requested {
                return Ok(latest.into_values().collect());
            }
        }
    }
}

impl NstatMeter {
    fn command(&mut self, command: &[u8]) -> Result<(), String> {
        self.stdin
            .write_all(command)
            .and_then(|()| self.stdin.flush())
            .map_err(|err| format!("meter command failed: {err}"))
    }
}

impl Drop for NstatMeter {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn meter_sample_names_a_process() {
        let path = env!("NETCHECK_METER_DEFAULT");
        if path.is_empty() {
            return;
        }
        let mut child = Command::new(path)
            .arg("--once")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn meter");
        let pid = child.id() as i32;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(8));
            unsafe { libc::kill(pid, libc::SIGKILL) };
        });
        let mut stdout = child.stdout.take().expect("stdout");
        read_magic(&mut stdout).expect("magic");
        let found = loop {
            match super::super::frame::read_sample(&mut stdout) {
                Ok(rows) if rows.is_empty() => continue,
                Ok(rows) => break rows,
                Err(err) => panic!("meter frame: {err}"),
            }
        };
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            found.iter().any(|sock| sock.pid > 0 && !sock.name.is_empty()),
            "expected a named process, got {} rows",
            found.len()
        );
    }
}
