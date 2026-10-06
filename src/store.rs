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
}
