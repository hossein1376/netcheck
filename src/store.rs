use crate::engine::{AppDelta, Buckets};
use crate::query::UsageRow;
use rusqlite::{params, Connection};
use std::path::Path;

const SCHEMA: &str = r#"
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
"#;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_read(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    pub fn flush(
        &self,
        apps: &[AppDelta],
        hour: i64,
        encap_rx: u64,
        encap_tx: u64,
    ) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for app in apps {
            let id: i64 = tx.query_row(
                "INSERT INTO app (app_key, display_name) VALUES (?1, ?2)
                 ON CONFLICT(app_key) DO UPDATE SET display_name = excluded.display_name
                 RETURNING id",
                params![app.app_key, app.display_name],
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
        if encap_rx > 0 || encap_tx > 0 {
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

    pub fn usage(&self, min_hour: i64, app: Option<&str>) -> rusqlite::Result<Vec<UsageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.app_key, a.display_name,
                    SUM(u.internet_rx), SUM(u.internet_tx),
                    SUM(u.local_rx), SUM(u.local_tx),
                    SUM(u.unscoped_rx), SUM(u.unscoped_tx)
             FROM usage_hour u
             JOIN app a ON a.id = u.app_id
             WHERE u.hour_utc >= ?1
               AND (?2 IS NULL OR INSTR(LOWER(a.display_name), LOWER(?2)) > 0)
             GROUP BY a.id
             ORDER BY (SUM(u.internet_rx) + SUM(u.internet_tx)
                     + SUM(u.unscoped_rx) + SUM(u.unscoped_tx)) DESC",
        )?;
        let rows = stmt.query_map(params![min_hour, app], |row| {
            Ok(UsageRow {
                app_key: row.get(0)?,
                display_name: row.get(1)?,
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

    #[test]
    fn flush_then_query_sums_the_hour() {
        let dir = std::env::temp_dir().join(format!("netcheck-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        let store = Store::open(&path).unwrap();
        store
            .flush(
                &[AppDelta {
                    app_key: "/usr/bin/curl".into(),
                    display_name: "curl".into(),
                    hour: 10,
                    buckets: Buckets {
                        internet_rx: 100,
                        internet_tx: 5,
                        ..Buckets::default()
                    },
                }],
                10,
                7,
                1,
            )
            .unwrap();
        store
            .flush(
                &[AppDelta {
                    app_key: "/usr/bin/curl".into(),
                    display_name: "curl".into(),
                    hour: 10,
                    buckets: Buckets {
                        internet_rx: 40,
                        ..Buckets::default()
                    },
                }],
                10,
                0,
                0,
            )
            .unwrap();
        let rows = store.usage(10, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].display_name, "curl");
        assert_eq!(rows[0].internet_rx, 140);
        assert_eq!(rows[0].internet_tx, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
