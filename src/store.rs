use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

// NOTE: This module is purely synchronous. Async wrappers must be applied at the call site
// (e.g., using `tokio::task::spawn_blocking`) when calling from an async context.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapOutcome {
    Granted,
    Denied(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Granted,
    Denied(String),
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
             PRAGMA foreign_keys=ON;",
        )?;
        let mut store = Self { conn };
        store.apply_schema()?;
        Ok(store)
    }

    pub fn apply_schema(&mut self) -> rusqlite::Result<()> {
        let schema = include_str!("../schema.sql");
        self.conn.execute_batch(schema)?;

        let tx = self.conn.transaction()?;
        let defaults = [
            ("grace_days", "5"),
            ("lockout_days", "10"),
            ("acl_expiry_days", "35"),
            ("acl_push_period_minutes", "60"),
            ("sync_interval_minutes", "60"),
        ];

        for (k, v) in defaults {
            tx.execute(
                "INSERT OR IGNORE INTO config (key, value) VALUES (?1, ?2)",
                params![k, v],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn enroll_tag(
        &mut self,
        uid: &str,
        member_key: &str,
        key_version: i64,
        timestamp: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO tags (uid, member_key, key_version, last_counter, status, enrolled_at)
             VALUES (?1, ?2, ?3, 0, 'active', ?4)
             ON CONFLICT(uid) DO UPDATE SET
             member_key = excluded.member_key,
             key_version = excluded.key_version,
             status = 'active',
             enrolled_at = excluded.enrolled_at",
            params![uid, member_key, key_version, timestamp],
        )?;
        Ok(())
    }

    pub fn revoke_tag(&mut self, uid: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE tags SET status = 'revoked' WHERE uid = ?1",
            params![uid],
        )?;
        Ok(())
    }

    pub fn record_tap(
        &mut self,
        uid: &str,
        counter: i64,
        device_id: Option<&str>,
        timestamp: &str,
        access_decision: AccessDecision,
    ) -> rusqlite::Result<TapOutcome> {
        // BEGIN IMMEDIATE so that if two threads try to update the counter, they serialize immediately.
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let current_counter: Option<i64> = tx
            .query_row(
                "SELECT last_counter FROM tags WHERE uid = ?1",
                params![uid],
                |row| row.get(0),
            )
            .optional()?;

        let (outcome, decision_str, reason_str) = match current_counter {
            Some(last) if counter <= last => (
                TapOutcome::Denied("counter_replay".to_string()),
                "denied".to_string(),
                "counter_replay".to_string(),
            ),
            Some(_) => {
                let dec = match &access_decision {
                    AccessDecision::Granted => "granted".to_string(),
                    AccessDecision::Denied(_) => "denied".to_string(),
                };
                let res = match &access_decision {
                    AccessDecision::Granted => "".to_string(),
                    AccessDecision::Denied(r) => r.clone(),
                };

                // Only update counter if the tag actually exists and counter is strictly greater
                tx.execute(
                    "UPDATE tags SET last_counter = ?1 WHERE uid = ?2",
                    params![counter, uid],
                )?;

                let tap_outcome = match access_decision {
                    AccessDecision::Granted => TapOutcome::Granted,
                    AccessDecision::Denied(r) => TapOutcome::Denied(r),
                };
                (tap_outcome, dec, res)
            }
            None => (
                TapOutcome::Denied("unknown_tag".to_string()),
                "denied".to_string(),
                "unknown_tag".to_string(),
            ),
        };

        tx.execute(
            "INSERT INTO audit_log (ts, device_id, uid, counter, decision, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![timestamp, device_id, uid, counter, decision_str, reason_str],
        )?;

        tx.commit()?;
        Ok(outcome)
    }

    pub fn get_config(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn set_config(&mut self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn set_presence(
        &mut self,
        device_id: &str,
        online: bool,
        timestamp: &str,
    ) -> rusqlite::Result<()> {
        let presence_str = if online { "online" } else { "offline" };
        let tx = self.conn.transaction()?;

        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1)",
            params![device_id],
            |row| row.get(0),
        )?;

        if exists {
            tx.execute(
                "UPDATE devices SET presence = ?1, last_seen = ?2 WHERE device_id = ?3",
                params![presence_str, timestamp, device_id],
            )?;
        } else {
            // If device doesn't exist, we just insert a default 'gate' role
            tx.execute(
                "INSERT INTO devices (device_id, role, presence, last_seen) VALUES (?1, 'gate', ?2, ?3)",
                params![device_id, presence_str, timestamp],
            )?;
        }

        tx.execute(
            "INSERT INTO audit_log (ts, device_id, uid, decision, reason)
             VALUES (?1, ?2, NULL, ?3, 'presence_update')",
            params![timestamp, device_id, presence_str],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn effective_access(&self, uid: &str, timestamp: &str) -> rusqlite::Result<AccessDecision> {
        let tag_row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT member_key, status FROM tags WHERE uid = ?1",
                params![uid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let (member_key, status) = match tag_row {
            Some(row) => row,
            None => return Ok(AccessDecision::Denied("unknown_tag".to_string())),
        };

        if status != "active" {
            return Ok(AccessDecision::Denied("tag_inactive".to_string()));
        }

        // Check overrides first
        let override_row: Option<String> = self
            .conn
            .query_row(
                "SELECT kind FROM overrides 
                 WHERE (uid = ?1 OR member_key = ?2) 
                   AND (expires_at IS NULL OR expires_at > ?3)
                 ORDER BY id DESC LIMIT 1",
                params![uid, member_key, timestamp],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(kind) = override_row {
            if kind == "ban" {
                return Ok(AccessDecision::Denied("override_ban".to_string()));
            } else if kind == "allow" {
                return Ok(AccessDecision::Granted);
            }
        }

        // Check member
        let active_until: Option<String> = self
            .conn
            .query_row(
                "SELECT active_until FROM members WHERE member_key = ?1",
                params![member_key],
                |row| row.get(0),
            )
            .optional()?;

        let active_until = match active_until {
            Some(au) => au,
            None => return Ok(AccessDecision::Denied("unknown_member".to_string())),
        };

        let grace_days = self
            .get_config("grace_days")?
            .unwrap_or_else(|| "5".to_string());
        let grace_days: i64 = grace_days.parse().unwrap_or(5);

        // SQLite date/time functions:
        // We compute if timestamp <= datetime(active_until, '+N days')
        // We use query_row because it handles the datetime manipulation easily.
        let is_within_grace: bool = self.conn.query_row(
            "SELECT ?1 <= datetime(?2, '+' || ?3 || ' days')",
            params![timestamp, active_until, grace_days],
            |row| row.get(0),
        )?;

        if is_within_grace {
            Ok(AccessDecision::Granted)
        } else {
            Ok(AccessDecision::Denied("member_inactive".to_string()))
        }
    }

    pub fn tag_exists(&self, uid: &str) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM tags WHERE uid = ?1)",
            params![uid],
            |row| row.get(0),
        )
    }

    pub fn audit_event(
        &mut self,
        timestamp: &str,
        device_id: Option<&str>,
        uid: Option<&str>,
        counter: Option<i64>,
        decision: &str,
        reason: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log (ts, device_id, uid, counter, decision, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![timestamp, device_id, uid, counter, decision, reason],
        )?;
        Ok(())
    }

    pub fn member_display_name(&self, uid: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT m.display_name
                 FROM tags t
                 JOIN members m ON m.member_key = t.member_key
                 WHERE t.uid = ?1",
                params![uid],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn presence_of(&self, device_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT presence FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn touch_last_seen(&mut self, device_id: &str, timestamp: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE devices SET last_seen = ?1 WHERE device_id = ?2",
            params![timestamp, device_id],
        )?;
        Ok(())
    }

    pub fn acl_devices(&self) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT device_id FROM devices WHERE offline_verify = 1")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect()
    }

    pub fn acl_tag_rows(&self) -> rusqlite::Result<Vec<(String, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.uid, m.active_until
             FROM tags t
             LEFT JOIN members m ON m.member_key = t.member_key
             WHERE t.status = 'active'",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    pub fn device_role(&self, device_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT role FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )
            .optional()
    }

    /// Create a single-use provisioning job; returns the generated job id.
    pub fn create_job(
        &mut self,
        uid: &str,
        member_key: &str,
        device_id: &str,
        created_at: &str,
        expires_at: &str,
    ) -> rusqlite::Result<String> {
        let job_id: String =
            self.conn
                .query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))?;
        self.conn.execute(
            "INSERT INTO jobs (job_id, uid, member_key, device_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![job_id, uid, member_key, device_id, created_at, expires_at],
        )?;
        Ok(job_id)
    }

    /// Atomically claim a job for consumption. Single-use: the `consumed_at`
    /// transition happens under an IMMEDIATE transaction so a concurrent
    /// second claim observes `AlreadyConsumed`.
    pub fn take_job(&mut self, job_id: &str, now: &str) -> rusqlite::Result<JobTake> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let row: Option<(String, String, String, String, Option<String>)> = tx
            .query_row(
                "SELECT uid, member_key, device_id, expires_at, consumed_at
                 FROM jobs WHERE job_id = ?1",
                params![job_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((uid, member_key, device_id, expires_at, consumed_at)) = row else {
            return Ok(JobTake::NotFound);
        };
        let job = JobRow {
            job_id: job_id.to_string(),
            uid,
            member_key,
            device_id,
            expires_at: expires_at.clone(),
            consumed_at,
        };
        if job.consumed_at.is_some() {
            return Ok(JobTake::AlreadyConsumed(job));
        }
        let expired = match chrono::DateTime::parse_from_rfc3339(&expires_at) {
            Ok(dt) => {
                let now_dt = chrono::DateTime::parse_from_rfc3339(now)
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now());
                dt.with_timezone(&chrono::Utc) <= now_dt
            }
            // Unparseable expiry is treated as expired (fail-safe: no redelivery).
            Err(_) => true,
        };
        if expired {
            return Ok(JobTake::Expired(job));
        }
        let changed = tx.execute(
            "UPDATE jobs SET consumed_at = ?1 WHERE job_id = ?2 AND consumed_at IS NULL",
            params![now, job_id],
        )?;
        if changed == 0 {
            return Ok(JobTake::AlreadyConsumed(job));
        }
        tx.commit()?;
        Ok(JobTake::Taken(job))
    }

    /// Enroll (or re-provision) a tag, setting `last_counter` from the card's
    /// current counter as reported by the writer.
    pub fn enroll_job_tag(
        &mut self,
        uid: &str,
        member_key: &str,
        key_version: i64,
        last_counter: i64,
        timestamp: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO tags (uid, member_key, key_version, last_counter, status, enrolled_at)
             VALUES (?1, ?2, ?3, ?4, 'active', ?5)
             ON CONFLICT(uid) DO UPDATE SET
             member_key = excluded.member_key,
             key_version = excluded.key_version,
             last_counter = excluded.last_counter,
             status = 'active',
             enrolled_at = excluded.enrolled_at",
            params![uid, member_key, key_version, last_counter, timestamp],
        )?;
        Ok(())
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

#[derive(Debug, Clone)]
pub struct JobRow {
    pub job_id: String,
    pub uid: String,
    pub member_key: String,
    pub device_id: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
}

#[derive(Debug)]
pub enum JobTake {
    Taken(JobRow),
    AlreadyConsumed(JobRow),
    Expired(JobRow),
    NotFound,
}
