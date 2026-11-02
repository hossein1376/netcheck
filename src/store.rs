use crate::engine::{AppDelta, Buckets};
use crate::group::group_of;
use crate::query::UsageRow;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;

/// Schema version this build reads and writes, kept in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 2;

/// Ordered upgrades. Step `i` takes the database from version `i` to `i + 1`.
/// Append new steps; never edit a released one.
const MIGRATIONS: [fn(&Connection) -> rusqlite::Result<()>; SCHEMA_VERSION as usize] =
    [base_tables, app_groups];

/// v1: the tables from the first release. A database made before versioning
/// is at v0 with these tables already present, so this is a no-op there.
fn base_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS app (
  id INTEGER PRIMARY KEY,
  app_key TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_hour (
  app_id INTEGER NOT NULL,
  hour_utc INTEGER NOT NULL,
  internet_rx INTEGER NOT NULL DEFAULT 0,
  internet_tx INTEGER NOT NULL DEFAULT 0,
  local_rx INTEGER NOT NULL DEFAULT 0,
  local_tx INTEGER NOT NULL DEFAULT 0,
  unscoped_rx INTEGER NOT NULL DEFAULT 0,
  unscoped_tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, hour_utc)
);
CREATE TABLE IF NOT EXISTS encapsulation_hour (
  hour_utc INTEGER PRIMARY KEY,
  rx INTEGER NOT NULL,
  tx INTEGER NOT NULL
);
"#,
    )
}

/// v2: the app each executable belongs to, filled in for existing rows.
fn app_groups(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "ALTER TABLE app ADD COLUMN group_key TEXT NOT NULL DEFAULT '';
         ALTER TABLE app ADD COLUMN group_name TEXT NOT NULL DEFAULT '';
         CREATE INDEX app_group ON app (group_key);",
    )?;
    let apps: Vec<(i64, String, String)> = conn
        .prepare("SELECT id, app_key, display_name FROM app")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut update = conn.prepare("UPDATE app SET group_key = ?1, group_name = ?2 WHERE id = ?3")?;
    for (id, app_key, display_name) in apps {
        let (group_key, group_name) = group_of(&app_key, &display_name);
        update.execute(params![group_key, group_name, id])?;
    }
    Ok(())
}

/// Run one migration and record its version, all or nothing.
fn apply(
    conn: &mut Connection,
    migrate: fn(&Connection) -> rusqlite::Result<()>,
    to: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    migrate(&tx)?;
    tx.pragma_update(None, "user_version", to)?;
    tx.commit()
}

fn user_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
}

/// How `usage` rows are keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    /// One row per app, helpers included.
    App,
    /// One row per executable.
    Executable,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open for writing, creating or upgrading the schema as needed.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let mut conn = Connection::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
        let setup = || -> rusqlite::Result<i64> {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            user_version(&conn)
        };
        let version = setup().map_err(|err| err.to_string())?;
        if version > SCHEMA_VERSION {
            return Err(format!(
                "the database at {} is schema v{version}, newer than this netcheck (v{SCHEMA_VERSION})",
                path.display()
            ));
        }
        for (step, migrate) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let to = step as i64 + 1;
            apply(&mut conn, *migrate, to)
                .map_err(|err| format!("upgrading the database to v{to}: {err}"))?;
        }
        Ok(Self { conn })
    }

    /// Open read-only. The daemon owns upgrades, so an old schema is an error.
    pub fn open_read(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("no database at {}", path.display()));
        }
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|err| format!("open {}: {err}", path.display()))?;
        let version = user_version(&conn).map_err(|err| err.to_string())?;
        if version < SCHEMA_VERSION {
            return Err(format!(
                "the database at {} is schema v{version}; restart the daemon to upgrade it to v{SCHEMA_VERSION}",
                path.display()
            ));
        }
        if version > SCHEMA_VERSION {
            return Err(format!(
                "the database at {} is schema v{version}, newer than this netcheck (v{SCHEMA_VERSION})",
                path.display()
            ));
        }
        Ok(Self { conn })
    }

    /// Add deltas to their hours in one transaction. `encap` maps hour to (rx, tx).
    pub fn flush(&self, apps: &[AppDelta], encap: &HashMap<i64, (u64, u64)>) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for app in apps {
            let id: i64 = tx.query_row(
                "INSERT INTO app (app_key, display_name, group_key, group_name) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(app_key) DO UPDATE SET
                    display_name = excluded.display_name,
                    group_key = excluded.group_key,
                    group_name = excluded.group_name
                 RETURNING id",
                params![app.app_key, app.display_name, app.group_key, app.group_name],
                |row| row.get(0),
            )?;
            let b: &Buckets = &app.buckets;
            tx.execute(
                "INSERT INTO usage_hour (
                    app_id, hour_utc, internet_rx, internet_tx, local_rx, local_tx, unscoped_rx, unscoped_tx
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(app_id, hour_utc) DO UPDATE SET
                    internet_rx = internet_rx + excluded.internet_rx,
                    internet_tx = internet_tx + excluded.internet_tx,
                    local_rx = local_rx + excluded.local_rx,
                    local_tx = local_tx + excluded.local_tx,
                    unscoped_rx = unscoped_rx + excluded.unscoped_rx,
                    unscoped_tx = unscoped_tx + excluded.unscoped_tx",
                params![
                    id,
                    app.hour,
                    b.internet_rx,
                    b.internet_tx,
                    b.local_rx,
                    b.local_tx,
                    b.unscoped_rx,
                    b.unscoped_tx
                ],
            )?;
        }
        for (hour, (encap_rx, encap_tx)) in encap {
            if *encap_rx == 0 && *encap_tx == 0 {
                continue;
            }
            tx.execute(
                "INSERT INTO encapsulation_hour (hour_utc, rx, tx) VALUES (?1, ?2, ?3)
                 ON CONFLICT(hour_utc) DO UPDATE SET
                    rx = rx + excluded.rx,
                    tx = tx + excluded.tx",
                params![hour, encap_rx, encap_tx],
            )?;
        }
        tx.commit()
    }

    /// Totals since `min_hour`, largest off-machine first. `app` filters by name.
    pub fn usage(&self, min_hour: i64, app: Option<&str>, by: By) -> rusqlite::Result<Vec<UsageRow>> {
        let (key, name, group) = match by {
            By::App => ("a.group_key", "MAX(a.group_name)", "a.group_key"),
            By::Executable => ("a.app_key", "a.display_name", "a.id"),
        };
        let filter = match by {
            By::App => "a.group_name",
            By::Executable => "a.display_name",
        };
        let sql = format!(
            "SELECT {key}, {name},
                    SUM(u.internet_rx), SUM(u.internet_tx),
                    SUM(u.local_rx), SUM(u.local_tx),
                    SUM(u.unscoped_rx), SUM(u.unscoped_tx)
             FROM usage_hour u
             JOIN app a ON a.id = u.app_id
             WHERE u.hour_utc >= ?1
               AND (?2 IS NULL OR INSTR(LOWER({filter}), LOWER(?2)) > 0)
             GROUP BY {group}
             ORDER BY (SUM(u.internet_rx) + SUM(u.internet_tx)
                     + SUM(u.unscoped_rx) + SUM(u.unscoped_tx)) DESC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![min_hour, app], |row| {
            Ok(UsageRow {
                key: row.get(0)?,
                name: row.get(1)?,
                internet_rx: row.get(2)?,
                internet_tx: row.get(3)?,
                local_rx: row.get(4)?,
                local_tx: row.get(5)?,
                unscoped_rx: row.get(6)?,
                unscoped_tx: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn hour_rows(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM usage_hour", [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Buckets;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("netcheck-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("t.db")
    }

    fn delta(app_key: &str, display: &str, rx: u64) -> AppDelta {
        let (group_key, group_name) = group_of(app_key, display);
        AppDelta {
            app_key: app_key.into(),
            display_name: display.into(),
            group_key,
            group_name,
            hour: 10,
            buckets: Buckets {
                internet_rx: rx,
                ..Buckets::default()
            },
        }
    }

    #[test]
    fn flush_then_query_sums_the_hour() {
        let path = scratch("store");
        let store = Store::open(&path).unwrap();
        store
            .flush(&[delta("/usr/bin/curl", "curl", 100)], &HashMap::from([(10, (7, 1))]))
            .unwrap();
        store
            .flush(&[delta("/usr/bin/curl", "curl", 40)], &HashMap::new())
            .unwrap();
        let rows = store.usage(10, None, By::App).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "curl");
        assert_eq!(rows[0].internet_rx, 140);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn helpers_sum_into_their_app_unless_asked_per_executable() {
        let path = scratch("groups");
        let store = Store::open(&path).unwrap();
        store
            .flush(
                &[
                    delta("/Applications/Claude.app/Contents/MacOS/Claude", "Claude", 100),
                    delta(
                        "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",
                        "Claude Helper",
                        50,
                    ),
                ],
                &HashMap::new(),
            )
            .unwrap();
        let apps = store.usage(10, None, By::App).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "Claude");
        assert_eq!(apps[0].key, "/Applications/Claude.app");
        assert_eq!(apps[0].internet_rx, 150);
        assert_eq!(store.usage(10, None, By::Executable).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_unversioned_database_is_upgraded_and_grouped() {
        let path = scratch("migrate");
        {
            let conn = Connection::open(&path).unwrap();
            base_tables(&conn).unwrap();
            conn.execute_batch(
                "INSERT INTO app (id, app_key, display_name) VALUES
                    (1, 'pid:50575:1793456084', 'curl'),
                    (2, '/usr/bin/curl', 'curl'),
                    (3, '/Applications/Zed.app/Contents/MacOS/zed', 'zed');
                 INSERT INTO usage_hour (app_id, hour_utc, internet_rx) VALUES (1, 10, 5), (2, 10, 7), (3, 10, 9);",
            )
            .unwrap();
        }
        let refused = Store::open_read(&path).err().expect("an old schema must be refused");
        assert!(refused.contains("restart the daemon"), "{refused}");

        let store = Store::open(&path).unwrap();
        assert_eq!(user_version(&store.conn).unwrap(), SCHEMA_VERSION);
        let rows = store.usage(10, None, By::App).unwrap();
        let names: Vec<(&str, u64)> = rows.iter().map(|r| (r.name.as_str(), r.internet_rx)).collect();
        assert!(names.contains(&("Zed", 9)), "{names:?}");
        assert!(rows.iter().any(|r| r.key == "/Applications/Zed.app"));
        assert!(rows.iter().any(|r| r.key == "name:curl" && r.internet_rx == 5));
        drop(store);
        assert!(Store::open_read(&path).is_ok());
        // Opening again runs no migration.
        Store::open(&path).unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
