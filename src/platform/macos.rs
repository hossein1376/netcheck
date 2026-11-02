//! macOS: a root LaunchDaemon, so the meter sees every process's sockets, not
//! just one user's. Data lives in /Library/Application Support/netcheck and is
//! readable by the admin group.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "com.netcheck.daemon";
/// The per-user agent of earlier versions, replaced on install.
const OLD_AGENT: &str = "com.netcheck.agent";
/// Group allowed to read usage data and ask the daemon for `top`.
pub const READER_GROUP: &str = "admin";

pub fn data_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/netcheck")
}

pub fn render_plist(bin: &Path, db: &Path, log: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>daemon</string>
    <string>--db</string>
    <string>{db}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        label = LABEL,
        bin = xml(&bin.display().to_string()),
        db = xml(&db.display().to_string()),
        log = xml(&log.display().to_string()),
    )
}

/// Copy the binaries and write the plist under `root` (`/` for a real install).
pub fn write_install(root: &Path, src_bin: &Path, src_meter: &Path, db: &Path) -> Result<PathBuf, String> {
    let bin_dir = root.join("Library/Application Support/netcheck/bin");
    fs::create_dir_all(&bin_dir).map_err(|err| err.to_string())?;
    let dest_bin = bin_dir.join("netcheck");
    copy_exe(src_bin, &dest_bin)?;
    copy_exe(src_meter, &bin_dir.join("nstat_meter"))?;

    let daemons = root.join("Library/LaunchDaemons");
    fs::create_dir_all(&daemons).map_err(|err| err.to_string())?;
    let log = root.join("Library/Logs/netcheck.log");
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let plist = daemons.join(format!("{LABEL}.plist"));
    fs::write(&plist, render_plist(&dest_bin, db, &log)).map_err(|err| err.to_string())?;
    // launchd refuses a daemon plist that others can write.
    fs::set_permissions(&plist, fs::Permissions::from_mode(0o644)).map_err(|err| err.to_string())?;
    Ok(plist)
}

pub fn install(src_bin: &Path, db: &Path) -> Result<(), String> {
    require_root("install")?;
    println!("Installs a LaunchDaemon that runs as root, starts at boot, and restarts if it exits.");
    let old = retire_user_agent();
    let _ = launchctl(&["bootout", &format!("system/{LABEL}")]);
    let plist = write_install(Path::new("/"), src_bin, &crate::meter::meter_path(), db)?;
    if let Some(dir) = db.parent() {
        fs::create_dir_all(dir).map_err(|err| err.to_string())?;
        super::share_with_readers(dir);
    }
    if let Some(old_db) = old.filter(|path| path.exists()) {
        if db.exists() {
            println!("kept the existing {}; the old {} was not copied", db.display(), old_db.display());
        } else {
            copy_database(&old_db, db)?;
            println!("copied usage history from {}", old_db.display());
            println!("the old copy is still there; delete it when you're happy");
        }
    }
    launchctl(&["bootstrap", "system", &plist.display().to_string()])?;
    launchctl(&["kickstart", "-k", &format!("system/{LABEL}")])?;
    println!("loaded {}", plist.display());
    println!("usage data is readable by the {READER_GROUP} group");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    require_root("uninstall")?;
    let plist = PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist"));
    let _ = launchctl(&["bootout", &format!("system/{LABEL}")]);
    if plist.exists() {
        fs::remove_file(&plist).map_err(|err| err.to_string())?;
    }
    let bin_dir = data_dir().join("bin");
    if bin_dir.exists() {
        fs::remove_dir_all(&bin_dir).map_err(|err| err.to_string())?;
    }
    println!("uninstalled {LABEL}");
    println!("left the usage database in {}", data_dir().display());
    Ok(())
}

fn require_root(what: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(format!("{what} needs root: run it with sudo"))
    }
}

/// Stop and remove the per-user agent of earlier versions for the user who ran
/// sudo. Returns where its database was, if there was one.
fn retire_user_agent() -> Option<PathBuf> {
    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let home = home_of(uid)?;
    let plist = home.join(format!("Library/LaunchAgents/{OLD_AGENT}.plist"));
    if plist.exists() {
        let _ = launchctl(&["bootout", &format!("gui/{uid}/{OLD_AGENT}")]);
        if fs::remove_file(&plist).is_ok() {
            println!("removed the old per-user agent {}", plist.display());
        }
    }
    let old_dir = home.join("Library/Application Support/netcheck");
    let _ = fs::remove_dir_all(old_dir.join("bin"));
    Some(old_dir.join("netcheck.db"))
}

fn home_of(uid: u32) -> Option<PathBuf> {
    let entry = unsafe { libc::getpwuid(uid) };
    if entry.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*entry).pw_dir) };
    Some(PathBuf::from(dir.to_str().ok()?))
}

/// A consistent copy, including anything still in the WAL.
fn copy_database(from: &Path, to: &Path) -> Result<(), String> {
    let conn = rusqlite::Connection::open(from).map_err(|err| format!("open {}: {err}", from.display()))?;
    conn.execute("VACUUM INTO ?1", [to.display().to_string()])
        .map_err(|err| format!("copy {} to {}: {err}", from.display(), to.display()))?;
    Ok(())
}

fn copy_exe(src: &Path, dest: &Path) -> Result<(), String> {
    if same_file(src, dest) {
        return Ok(());
    }
    // Copy to a new file and rename over the old one. Writing into an executable
    // that has run leaves macOS with a stale code signature for it, and the next
    // launch is killed.
    let tmp = dest.with_extension("new");
    let _ = fs::remove_file(&tmp);
    fs::copy(src, &tmp).map_err(|err| format!("copy {} failed: {err}", src.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(|err| err.to_string())?;
    fs::rename(&tmp, dest).map_err(|err| format!("replace {} failed: {err}", dest.display()))?;
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn launchctl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("launchctl")
        .args(args)
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("launchctl {} exited {status}", args.first().unwrap_or(&"")))
    }
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_runs_the_daemon_in_the_background() {
        let text = render_plist(
            Path::new("/Apps/netcheck"),
            Path::new("/Data/netcheck.db"),
            Path::new("/Logs/netcheck.log"),
        );
        assert!(text.contains(LABEL));
        assert!(text.contains("/Apps/netcheck"));
        assert!(text.contains(">daemon<"));
        assert!(text.contains("/Data/netcheck.db"));
        assert!(text.contains("<key>KeepAlive</key>"));
        assert!(text.contains("<string>Background</string>"));
    }

    #[test]
    fn write_install_lays_out_a_launch_daemon() {
        let root = std::env::temp_dir().join(format!("netcheck-install-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("netcheck"), b"bin").unwrap();
        fs::write(src.join("nstat_meter"), b"meter").unwrap();
        let db = root.join("Library/Application Support/netcheck/netcheck.db");
        let plist = write_install(&root, &src.join("netcheck"), &src.join("nstat_meter"), &db).unwrap();
        assert_eq!(plist, root.join(format!("Library/LaunchDaemons/{LABEL}.plist")));
        assert_eq!(fs::metadata(&plist).unwrap().permissions().mode() & 0o777, 0o644);
        let bin_dir = root.join("Library/Application Support/netcheck/bin");
        assert_eq!(fs::read(bin_dir.join("nstat_meter")).unwrap(), b"meter");

        // A reinstall replaces the file rather than writing into it.
        use std::os::unix::fs::MetadataExt;
        let before = fs::metadata(bin_dir.join("netcheck")).unwrap().ino();
        fs::write(src.join("netcheck"), b"bin2").unwrap();
        write_install(&root, &src.join("netcheck"), &src.join("nstat_meter"), &db).unwrap();
        let after = fs::metadata(bin_dir.join("netcheck")).unwrap();
        assert_eq!(fs::read(bin_dir.join("netcheck")).unwrap(), b"bin2");
        assert_ne!(after.ino(), before, "the running binary's inode must not be rewritten");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn copy_database_includes_the_wal() {
        let dir = std::env::temp_dir().join(format!("netcheck-copy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let from = dir.join("old.db");
        let conn = rusqlite::Connection::open(&from).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (42);").unwrap();
        // Keep `conn` open so the row is still only in the WAL.
        copy_database(&from, &dir.join("new.db")).unwrap();
        let copy = rusqlite::Connection::open(dir.join("new.db")).unwrap();
        let x: i64 = copy.query_row("SELECT x FROM t", [], |row| row.get(0)).unwrap();
        assert_eq!(x, 42);
        drop(conn);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_refuses_without_root() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert!(install(Path::new("/nonexistent"), Path::new("/nonexistent.db"))
            .unwrap_err()
            .contains("sudo"));
    }
}
