//! macOS meter: the `nstat_meter` helper reads NetworkStatistics and streams
//! NC02 frames over a pipe.

use super::frame::{read_magic, read_sample};
use super::{Meter, SocketCount};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};

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
    stdout: ChildStdout,
}

impl NstatMeter {
    pub fn spawn() -> Result<Self, String> {
        let meter = meter_path();
        if !meter.exists() {
            return Err(format!("meter binary is missing at {}", meter.display()));
        }
        let mut child = Command::new(&meter)
            .stdin(Stdio::null())
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
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("meter stdout is missing".into());
        };
        // Wrap now so a bad header still kills the child on drop.
        let mut meter = Self { child, stdout };
        read_magic(&mut meter.stdout).map_err(|err| err.to_string())?;
        Ok(meter)
    }
}

impl Meter for NstatMeter {
    fn backend(&self) -> &'static str {
        "networkstatistics"
    }

    fn next_sample(&mut self) -> Result<Vec<SocketCount>, String> {
        read_sample(&mut self.stdout).map_err(|err| err.to_string())
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
            match read_sample(&mut stdout) {
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
