use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use crate::sync_projection::{
    RosterEntry, FLAG_EXPIRY_ABSENT, FLAG_OVERRIDDEN_ALLOW, FLAG_OVERRIDDEN_BAN, FLAG_REVOKED,
    ROSTER_ENTRY_SIZE,
};

fn parse_uid_7(uid_str: &str) -> [u8; 7] {
    let mut uid = [0u8; 7];
    if let Ok(bytes) = hex::decode(uid_str) {
        let len = bytes.len().min(7);
        uid[..len].copy_from_slice(&bytes[..len]);
    } else {
        let bytes = uid_str.as_bytes();
        let len = bytes.len().min(7);
        uid[..len].copy_from_slice(&bytes[..len]);
    }
    uid
}

fn bump_roster_gen_in_tx(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<u64> {
    let current_gen: i64 = tx
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM config WHERE key = 'roster_gen'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    let new_gen = (current_gen.max(0) as u64) + 1;
    tx.execute(
        "INSERT INTO config (key, value) VALUES ('roster_gen', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![new_gen.to_string()],
    )?;
    Ok(new_gen)
}

pub(crate) fn record_roster_event_for_tag_in_tx(
    tx: &rusqlite::Transaction<'_>,
    uid: &str,
    timestamp: &str,
) -> rusqlite::Result<u64> {
    let new_roster_gen: u64 = bump_roster_gen_in_tx(tx)?;

    let tag_row: Option<(String, i64, i64, String, i64)> = tx
        .query_row(
            "SELECT member_key, key_version, last_counter, status, entry_gen FROM tags WHERE uid = ?1",
            params![uid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;

    let Some((member_key, key_version, last_counter, status, entry_gen)) = tag_row else {
        return Ok(new_roster_gen);
    };

    let active_until: Option<String> = tx
        .query_row(
            "SELECT active_until FROM members WHERE member_key = ?1",
            params![member_key],
            |r| r.get(0),
        )
        .optional()?;

    let override_kind: Option<String> = tx
        .query_row(
            "SELECT kind FROM overrides
             WHERE (uid = ?1 OR member_key = ?2)
               AND (expires_at IS NULL OR expires_at > ?3)
             ORDER BY id DESC LIMIT 1",
            params![uid, member_key, timestamp],
            |r| r.get(0),
        )
        .optional()?;

    let mut flags = 0u8;
    if status != "active" {
        flags |= FLAG_REVOKED;
    }
    if let Some(kind) = override_kind {
        if kind == "ban" {
            flags |= FLAG_OVERRIDDEN_BAN;
        } else if kind == "allow" {
            flags |= FLAG_OVERRIDDEN_ALLOW;
        }
    }

    let expiry_epoch = match active_until
        .as_deref()
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
    {
        Some(dt) => dt.timestamp().max(0) as u32,
        None => {
            flags |= FLAG_EXPIRY_ABSENT;
            0
        }
    };

    let entry = RosterEntry {
        uid: parse_uid_7(uid),
        counter: last_counter as u32,
        expiry_epoch,
        key_version: key_version as u8,
        entry_gen: entry_gen as u32,
        flags,
    };

    let blob_hex = hex::encode(entry.to_bytes());
    tx.execute(
        "INSERT INTO roster_events (roster_gen, uid, entry_blob, ts)
         VALUES (?1, ?2, ?3, ?4)",
        params![new_roster_gen as i64, uid, blob_hex, timestamp],
    )?;

    Ok(new_roster_gen)
}

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
        Self::apply_schema_to(&self.conn)?;

        let tx = self.conn.transaction()?;
        let defaults = [
            ("grace_days", "5"),
            ("lockout_days", "10"),
            ("acl_expiry_days", "35"),
            ("acl_push_period_minutes", "60"),
            ("sync_interval_minutes", "60"),
            ("roster_gen", "0"),
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

    /// Idempotent schema application, including the one-active-tag-per-member
    /// migration (see schema.sql). Split out so the migration itself is
    /// unit-testable against pre-existing data.
    fn apply_schema_to(conn: &Connection) -> rusqlite::Result<()> {
        let schema = include_str!("../schema.sql");
        conn.execute_batch(schema)?;

        // v0.4.0 migration: phone column for the SUN tap landing page.
        // CREATE TABLE IF NOT EXISTS does not extend pre-existing tables, so
        // the column is added conditionally.
        let has_phone: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('members') WHERE name = 'phone')",
            [],
            |row| row.get(0),
        )?;
        if !has_phone {
            conn.execute("ALTER TABLE members ADD COLUMN phone TEXT", [])?;
        }

        // v0.5.0 additive migrations (keygate-offline-first-reader S1 groundwork):
        // 1. tags.entry_gen INTEGER NOT NULL DEFAULT 1
        let has_entry_gen: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tags') WHERE name = 'entry_gen')",
            [],
            |row| row.get(0),
        )?;
        if !has_entry_gen {
            conn.execute(
                "ALTER TABLE tags ADD COLUMN entry_gen INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }

        // 2. audit_log.member_key TEXT (nullable)
        let has_member_key: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('audit_log') WHERE name = 'member_key')",
            [],
            |row| row.get(0),
        )?;
        if !has_member_key {
            conn.execute("ALTER TABLE audit_log ADD COLUMN member_key TEXT", [])?;
        }

        Ok(())
    }

    pub fn enroll_tag(
        &mut self,
        uid: &str,
        member_key: &str,
        key_version: i64,
        timestamp: &str,
    ) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        // Replacement semantics: a member holds at most one active tag. The
        // partial unique index (idx_tags_one_active_per_member) enforces the
        // invariant at the storage layer; this revoke must run first so the
        // upsert below does not collide with the member's previous tag.
        let replaced_uids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT uid FROM tags WHERE member_key = ?1 AND uid != ?2 AND status = 'active'",
            )?;
            let rows = stmt.query_map(params![member_key, uid], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };

        for r_uid in replaced_uids {
            tx.execute(
                "UPDATE tags SET status = 'revoked', entry_gen = entry_gen + 1 WHERE uid = ?1",
                params![r_uid],
            )?;
            record_roster_event_for_tag_in_tx(&tx, &r_uid, timestamp)?;
        }

        tx.execute(
            "INSERT INTO tags (uid, member_key, key_version, last_counter, status, enrolled_at, entry_gen)
             VALUES (?1, ?2, ?3, 0, 'active', ?4, 1)
             ON CONFLICT(uid) DO UPDATE SET
             member_key = excluded.member_key,
             key_version = excluded.key_version,
             status = 'active',
             enrolled_at = excluded.enrolled_at,
             entry_gen = tags.entry_gen + 1",
            params![uid, member_key, key_version, timestamp],
        )?;
        record_roster_event_for_tag_in_tx(&tx, uid, timestamp)?;

        tx.commit()?;
        Ok(())
    }

    pub fn revoke_tag(&mut self, uid: &str) -> rusqlite::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let tx = self.conn.transaction()?;
        let is_active: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tags WHERE uid = ?1 AND status = 'active')",
                params![uid],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false);

        if is_active {
            tx.execute(
                "UPDATE tags SET status = 'revoked', entry_gen = entry_gen + 1 WHERE uid = ?1",
                params![uid],
            )?;
            record_roster_event_for_tag_in_tx(&tx, uid, &now)?;
        }
        tx.commit()?;
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

        let member_key: Option<String> = tx
            .query_row(
                "SELECT member_key FROM tags WHERE uid = ?1",
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
            "INSERT INTO audit_log (ts, device_id, uid, counter, decision, reason, member_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                timestamp,
                device_id,
                uid,
                counter,
                decision_str,
                reason_str,
                member_key
            ],
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
            // Roster absence (sync removed the member — e.g. they left the
            // Authentik membership group) means the membership lapsed: the
            // person is an ex-member. The tag itself is known and enrolled;
            // it is the membership that expired.
            None => return Ok(AccessDecision::Denied("expired_membership".to_string())),
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
            Ok(AccessDecision::Denied("expired_membership".to_string()))
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
        self.audit_event_with_member(timestamp, device_id, uid, counter, decision, reason, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn audit_event_with_member(
        &mut self,
        timestamp: &str,
        device_id: Option<&str>,
        uid: Option<&str>,
        counter: Option<i64>,
        decision: &str,
        reason: &str,
        member_key: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log (ts, device_id, uid, counter, decision, reason, member_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![timestamp, device_id, uid, counter, decision, reason, member_key],
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

    /// Single tag lookup by UID (any status).
    pub fn tag_by_uid(&self, uid: &str) -> rusqlite::Result<Option<TagInfo>> {
        self.conn
            .query_row(
                "SELECT uid, member_key, status, key_version, last_counter, enrolled_at, entry_gen
                 FROM tags WHERE uid = ?1",
                params![uid],
                |r| {
                    Ok(TagInfo {
                        uid: r.get(0)?,
                        member_key: r.get(1)?,
                        status: r.get(2)?,
                        key_version: r.get(3)?,
                        last_counter: r.get(4)?,
                        enrolled_at: r.get(5)?,
                        entry_gen: r.get(6)?,
                    })
                },
            )
            .optional()
    }

    /// Roster contact for a member: display name plus phone (when synced).
    pub fn member_contact(
        &self,
        member_key: &str,
    ) -> rusqlite::Result<Option<(String, Option<String>)>> {
        self.conn
            .query_row(
                "SELECT display_name, phone FROM members WHERE member_key = ?1",
                params![member_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
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

    /// Set a device's role. Roles outside `{gate, writer, both}` are rejected
    /// (`Ok(false)`); returns `false` also when the device is unknown.
    pub fn set_device_role(&mut self, device_id: &str, role: &str) -> rusqlite::Result<bool> {
        if !matches!(role, "gate" | "writer" | "both") {
            return Ok(false);
        }
        let changed = self.conn.execute(
            "UPDATE devices SET role = ?1 WHERE device_id = ?2",
            params![role, device_id],
        )?;
        Ok(changed > 0)
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
        if job_expired(&expires_at, now) {
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

    /// Live (unconsumed, unexpired) provisioning jobs, newest first — the
    /// admin UI's pending list (T6). `device` filters to one writer.
    pub fn pending_jobs(
        &self,
        device: Option<&str>,
        now: &str,
    ) -> rusqlite::Result<Vec<PendingJobRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT job_id, uid, member_key, device_id, created_at, expires_at
             FROM jobs
             WHERE consumed_at IS NULL AND expires_at > ?1
               AND (?2 IS NULL OR device_id = ?2)
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![now, device], |row| {
            Ok(PendingJobRow {
                job_id: row.get(0)?,
                uid: row.get(1)?,
                member_key: row.get(2)?,
                device_id: row.get(3)?,
                created_at: row.get(4)?,
                expires_at: row.get(5)?,
                consumed_at: None,
                outcome: None,
                reason: None,
            })
        })?;
        rows.collect()
    }

    /// Claim a job for a specific tag id. A wildcard job (empty `uid`) binds
    /// its uid on first claim; a fixed-uid job never changes its uid. Single-use
    /// semantics mirror `take_job`; the uid transition commits under an
    /// IMMEDIATE transaction so a concurrent claim observes the bound uid.
    pub fn claim_job(
        &mut self,
        job_id: &str,
        uid_hex: &str,
        now: &str,
    ) -> rusqlite::Result<JobClaim> {
        self.claim_job_on_device(job_id, uid_hex, now, "")
    }

    pub fn claim_job_on_device(
        &mut self,
        job_id: &str,
        uid_hex: &str,
        now: &str,
        device: &str,
    ) -> rusqlite::Result<JobClaim> {
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
            return Ok(JobClaim::NotFound);
        };
        // Wildcard device targeting ("*"): if job was created for wildcard device,
        // bind the job to the claiming device upon first claim.
        let device_id = if device_id == "*" {
            tx.execute(
                "UPDATE jobs SET device_id = ?1 WHERE job_id = ?2 AND device_id = '*'",
                params![device, job_id],
            )?;
            device.to_string()
        } else {
            device_id
        };
        let job = JobRow {
            job_id: job_id.to_string(),
            uid: uid.clone(),
            member_key,
            device_id,
            expires_at: expires_at.clone(),
            consumed_at: consumed_at.clone(),
        };
        if consumed_at.is_some() {
            return Ok(JobClaim::Consumed(job));
        }
        if job_expired(&expires_at, now) {
            return Ok(JobClaim::Expired(job));
        }
        if uid.is_empty() {
            tx.execute(
                "UPDATE jobs SET uid = ?1 WHERE job_id = ?2 AND uid = ''",
                params![uid_hex, job_id],
            )?;
            tx.commit()?;
            let claimed = JobRow {
                uid: uid_hex.to_string(),
                ..job
            };
            return Ok(JobClaim::Claimed(claimed));
        }
        if uid.eq_ignore_ascii_case(uid_hex) {
            return Ok(JobClaim::Claimed(job));
        }
        Ok(JobClaim::UidMismatch(job))
    }

    /// Mark a job consumed without enrollment (writer failure or admin cancel).
    /// Audits `job_failed`. Returns `false` when the job is unknown.
    pub fn fail_job(&mut self, job_id: &str, now: &str, reason: &str) -> rusqlite::Result<bool> {
        let row: Option<(String, String, Option<String>, String)> = self
            .conn
            .query_row(
                "SELECT device_id, uid, consumed_at, member_key FROM jobs WHERE job_id = ?1",
                params![job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((device_id, uid, consumed_at, member_key)) = row else {
            return Ok(false);
        };
        if consumed_at.is_none() {
            self.conn.execute(
                "UPDATE jobs SET consumed_at = ?1 WHERE job_id = ?2 AND consumed_at IS NULL",
                params![now, job_id],
            )?;
        }
        tracing::info!(job_id, member_key = %member_key, reason, "job failed");
        let uid_opt = if uid.is_empty() {
            None
        } else {
            Some(uid.as_str())
        };
        self.audit_event_with_member(
            now,
            Some(&device_id),
            uid_opt,
            None,
            "denied",
            "job_failed",
            Some(&member_key),
        )?;
        Ok(true)
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
        let tx = self.conn.transaction()?;
        // Replacement semantics (see enroll_tag): the member's other tags
        // become inert the moment this one is accepted. The unique partial
        // index makes a second active tag unrepresentable; revoke first.
        let replaced_uids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT uid FROM tags WHERE member_key = ?1 AND uid != ?2 AND status = 'active'",
            )?;
            let rows = stmt.query_map(params![member_key, uid], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };

        for r_uid in replaced_uids {
            tx.execute(
                "UPDATE tags SET status = 'revoked', entry_gen = entry_gen + 1 WHERE uid = ?1",
                params![r_uid],
            )?;
            record_roster_event_for_tag_in_tx(&tx, &r_uid, timestamp)?;
        }

        tx.execute(
            "INSERT INTO tags (uid, member_key, key_version, last_counter, status, enrolled_at, entry_gen)
             VALUES (?1, ?2, ?3, ?4, 'active', ?5, 1)
             ON CONFLICT(uid) DO UPDATE SET
             member_key = excluded.member_key,
             key_version = excluded.key_version,
             last_counter = excluded.last_counter,
             status = 'active',
             enrolled_at = excluded.enrolled_at,
             entry_gen = tags.entry_gen + 1",
            params![uid, member_key, key_version, last_counter, timestamp],
        )?;
        record_roster_event_for_tag_in_tx(&tx, uid, timestamp)?;

        tx.commit()?;
        Ok(())
    }

    pub fn list_tags(&self) -> rusqlite::Result<Vec<TagInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT uid, member_key, status, key_version, last_counter, enrolled_at, entry_gen
             FROM tags ORDER BY enrolled_at, uid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(TagInfo {
                uid: r.get(0)?,
                member_key: r.get(1)?,
                status: r.get(2)?,
                key_version: r.get(3)?,
                last_counter: r.get(4)?,
                enrolled_at: r.get(5)?,
                entry_gen: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_members(&self) -> rusqlite::Result<Vec<MemberInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_key, display_name, active_until, source
             FROM members ORDER BY member_key",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(MemberInfo {
                member_key: r.get(0)?,
                display_name: r.get(1)?,
                active_until: r.get(2)?,
                source: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_writer_devices(&self) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id FROM devices WHERE role IN ('writer', 'both') ORDER BY device_id",
        )?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    pub fn list_devices(&self) -> rusqlite::Result<Vec<DeviceInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, role, offline_verify, presence, last_seen
             FROM devices ORDER BY device_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(DeviceInfo {
                device_id: r.get(0)?,
                role: r.get(1)?,
                offline_verify: r.get(2)?,
                presence: r.get(3)?,
                last_seen: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn upsert_device(
        &mut self,
        device_id: &str,
        role: &str,
        offline_verify: bool,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO devices (device_id, role, offline_verify)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(device_id) DO UPDATE SET
               role = excluded.role,
               offline_verify = excluded.offline_verify",
            params![device_id, role, offline_verify],
        )?;
        Ok(())
    }

    pub fn list_audit(
        &self,
        limit: u32,
        uid: Option<&str>,
        decision: Option<&str>,
    ) -> rusqlite::Result<Vec<AuditInfo>> {
        let mut sql = String::from(
            "SELECT id, ts, device_id, uid, counter, decision, reason, member_key
             FROM audit_log WHERE 1=1",
        );
        let mut binds: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(u) = uid {
            binds.push(rusqlite::types::Value::Text(u.to_string()));
            sql.push_str(&format!(" AND uid = ?{}", binds.len()));
        }
        if let Some(d) = decision {
            binds.push(rusqlite::types::Value::Text(d.to_string()));
            sql.push_str(&format!(" AND decision = ?{}", binds.len()));
        }
        binds.push(rusqlite::types::Value::Integer(i64::from(limit)));
        sql.push_str(&format!(" ORDER BY id DESC LIMIT ?{}", binds.len()));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(binds), |r| {
            Ok(AuditInfo {
                id: r.get(0)?,
                ts: r.get(1)?,
                device_id: r.get(2)?,
                uid: r.get(3)?,
                counter: r.get(4)?,
                decision: r.get(5)?,
                reason: r.get(6)?,
                member_key: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_override(
        &mut self,
        member_key: Option<&str>,
        uid: Option<&str>,
        kind: &str,
        expires_at: Option<&str>,
        note: Option<&str>,
        created_at: &str,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO overrides (member_key, uid, kind, expires_at, note, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![member_key, uid, kind, expires_at, note, created_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_overrides(&self) -> rusqlite::Result<Vec<OverrideInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, member_key, uid, kind, expires_at, note, created_at
             FROM overrides ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(OverrideInfo {
                id: r.get(0)?,
                member_key: r.get(1)?,
                uid: r.get(2)?,
                kind: r.get(3)?,
                expires_at: r.get(4)?,
                note: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn sync_state(&self) -> rusqlite::Result<Option<SyncStateInfo>> {
        self.conn
            .query_row(
                "SELECT last_success, last_attempt, detail FROM sync_state WHERE id = 1",
                [],
                |r| {
                    Ok(SyncStateInfo {
                        last_success: r.get(0)?,
                        last_attempt: r.get(1)?,
                        detail: r.get(2)?,
                    })
                },
            )
            .optional()
    }

    pub fn list_config(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM config ORDER BY key")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    pub fn get_member(&self, member_key: &str) -> rusqlite::Result<Option<MemberInfo>> {
        self.conn
            .query_row(
                "SELECT member_key, display_name, active_until, source
                 FROM members WHERE member_key = ?1",
                params![member_key],
                |r| {
                    Ok(MemberInfo {
                        member_key: r.get(0)?,
                        display_name: r.get(1)?,
                        active_until: r.get(2)?,
                        source: r.get(3)?,
                    })
                },
            )
            .optional()
    }

    pub fn is_member_active(&self, member_key: &str, timestamp: &str) -> rusqlite::Result<bool> {
        let override_row: Option<String> = self
            .conn
            .query_row(
                "SELECT kind FROM overrides 
                 WHERE member_key = ?1 
                   AND (expires_at IS NULL OR expires_at > ?2)
                 ORDER BY id DESC LIMIT 1",
                params![member_key, timestamp],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(kind) = override_row {
            if kind == "ban" {
                return Ok(false);
            } else if kind == "allow" {
                return Ok(true);
            }
        }

        let active_until: Option<String> = self
            .conn
            .query_row(
                "SELECT active_until FROM members WHERE member_key = ?1",
                params![member_key],
                |row| row.get(0),
            )
            .optional()?;

        let Some(au) = active_until else {
            return Ok(false);
        };

        let grace_days = self
            .get_config("grace_days")?
            .unwrap_or_else(|| "5".to_string());
        let grace_days: i64 = grace_days.parse().unwrap_or(5);

        let is_within_grace: bool = self.conn.query_row(
            "SELECT ?1 <= datetime(?2, '+' || ?3 || ' days')",
            params![timestamp, au, grace_days],
            |row| row.get(0),
        )?;

        Ok(is_within_grace)
    }

    pub fn get_active_tag_for_member(&self, member_key: &str) -> rusqlite::Result<Option<TagInfo>> {
        self.conn
            .query_row(
                "SELECT uid, member_key, status, key_version, last_counter, enrolled_at, entry_gen
                 FROM tags WHERE member_key = ?1 AND status = 'active'",
                params![member_key],
                |r| {
                    Ok(TagInfo {
                        uid: r.get(0)?,
                        member_key: r.get(1)?,
                        status: r.get(2)?,
                        key_version: r.get(3)?,
                        last_counter: r.get(4)?,
                        enrolled_at: r.get(5)?,
                        entry_gen: r.get(6)?,
                    })
                },
            )
            .optional()
    }

    pub fn list_tags_for_member(&self, member_key: &str) -> rusqlite::Result<Vec<TagInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT uid, member_key, status, key_version, last_counter, enrolled_at, entry_gen
             FROM tags WHERE member_key = ?1 ORDER BY enrolled_at DESC, uid",
        )?;
        let rows = stmt.query_map(params![member_key], |r| {
            Ok(TagInfo {
                uid: r.get(0)?,
                member_key: r.get(1)?,
                status: r.get(2)?,
                key_version: r.get(3)?,
                last_counter: r.get(4)?,
                enrolled_at: r.get(5)?,
                entry_gen: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn revoke_active_tags_for_member(
        &mut self,
        member_key: &str,
    ) -> rusqlite::Result<Vec<String>> {
        let now = chrono::Utc::now().to_rfc3339();
        let tx = self.conn.transaction()?;
        let uids: Vec<String> = {
            let mut stmt =
                tx.prepare("SELECT uid FROM tags WHERE member_key = ?1 AND status = 'active'")?;
            let rows = stmt.query_map(params![member_key], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };

        for uid in &uids {
            tx.execute(
                "UPDATE tags SET status = 'revoked', entry_gen = entry_gen + 1 WHERE uid = ?1",
                params![uid],
            )?;
            record_roster_event_for_tag_in_tx(&tx, uid, &now)?;
        }
        tx.commit()?;
        Ok(uids)
    }

    pub fn pending_job_for_member(
        &self,
        member_key: &str,
        now: &str,
    ) -> rusqlite::Result<Option<PendingJobRow>> {
        self.conn
            .query_row(
                "SELECT job_id, uid, member_key, device_id, created_at, expires_at
                 FROM jobs
                 WHERE member_key = ?1 AND consumed_at IS NULL AND expires_at > ?2
                 ORDER BY created_at DESC LIMIT 1",
                params![member_key, now],
                |row| {
                    Ok(PendingJobRow {
                        job_id: row.get(0)?,
                        uid: row.get(1)?,
                        member_key: row.get(2)?,
                        device_id: row.get(3)?,
                        created_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        consumed_at: None,
                        outcome: None,
                        reason: None,
                    })
                },
            )
            .optional()
    }

    /// Retrieve the most recent provisioning job for a member, regardless of whether it is
    /// pending, completed, or failed.
    pub fn latest_job_for_member(
        &self,
        member_key: &str,
    ) -> rusqlite::Result<Option<MemberJobStatus>> {
        #[allow(clippy::type_complexity)]
        let row: Option<(
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        )> = self
            .conn
            .query_row(
                "SELECT job_id, uid, member_key, device_id, created_at, expires_at, consumed_at
                 FROM jobs
                 WHERE member_key = ?1
                 ORDER BY created_at DESC LIMIT 1",
                params![member_key],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()?;

        let Some((job_id, uid, member_key, device_id, created_at, expires_at, consumed_at)) = row
        else {
            return Ok(None);
        };

        let mut outcome = None;
        let mut reason = None;

        if consumed_at.is_some() {
            // Check audit log for this job's outcome
            let audit_row: Option<(String, String)> = self
                .conn
                .query_row(
                    "SELECT decision, reason FROM audit_log
                     WHERE (reason = 'job_done' OR reason = 'job_failed' OR reason = 'cancelled')
                       AND ts >= ?1
                     ORDER BY id DESC LIMIT 1",
                    params![created_at],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            if let Some((dec, r)) = audit_row {
                if r == "job_done" && dec == "granted" {
                    outcome = Some("enrolled".to_string());
                } else if r == "cancelled" {
                    outcome = Some("cancelled".to_string());
                    reason = Some("Job was cancelled by an admin.".to_string());
                } else {
                    outcome = Some("failed".to_string());
                    reason = Some(r);
                }
            } else {
                outcome = Some("consumed".to_string());
            }
        }

        Ok(Some(MemberJobStatus {
            job_id,
            uid,
            member_key,
            device_id,
            created_at,
            expires_at,
            consumed_at,
            outcome,
            reason,
        }))
    }

    pub fn list_audit_for_uids(
        &self,
        uids: &[String],
        limit: u32,
    ) -> rusqlite::Result<Vec<AuditInfo>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders: Vec<String> = (1..=uids.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT id, ts, device_id, uid, counter, decision, reason, member_key
             FROM audit_log
             WHERE uid IN ({})
             ORDER BY id DESC LIMIT ?{}",
            placeholders.join(","),
            uids.len() + 1
        );
        let mut binds: Vec<rusqlite::types::Value> = uids
            .iter()
            .map(|u| rusqlite::types::Value::Text(u.clone()))
            .collect();
        binds.push(rusqlite::types::Value::Integer(i64::from(limit)));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(binds), |r| {
            Ok(AuditInfo {
                id: r.get(0)?,
                ts: r.get(1)?,
                device_id: r.get(2)?,
                uid: r.get(3)?,
                counter: r.get(4)?,
                decision: r.get(5)?,
                reason: r.get(6)?,
                member_key: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_anomalies(&self) -> rusqlite::Result<Vec<AnomalyRow>> {
        self.list_anomalies_filtered(50, None, None)
    }

    pub fn tap_report_by_id(&self, tap_id: &str) -> rusqlite::Result<Option<TapReportRow>> {
        self.conn
            .query_row(
                "SELECT tap_id, device_id, uid, counter, decision, reason, time_uncertain, dev_ts, recv_ts, key_version, kind
                 FROM tap_reports WHERE tap_id = ?1",
                params![tap_id],
                |r| {
                    Ok(TapReportRow {
                        tap_id: r.get(0)?,
                        device_id: r.get(1)?,
                        uid: r.get(2)?,
                        counter: r.get(3)?,
                        decision: r.get(4)?,
                        reason: r.get(5)?,
                        time_uncertain: r.get(6)?,
                        dev_ts: r.get(7)?,
                        recv_ts: r.get(8)?,
                        key_version: r.get(9)?,
                        kind: r.get(10)?,
                    })
                },
            )
            .optional()
    }

    pub fn record_anomaly(
        &mut self,
        ts: &str,
        device_id: Option<&str>,
        uid: Option<&str>,
        kind: &str,
        detail: Option<&str>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO anomalies (ts, device_id, uid, kind, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ts, device_id, uid, kind, detail],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Ingest a tap report or tap consult idempotently (Task 3 / D2).
    ///
    /// Semantics:
    /// - Duplicate `tap_id`: returns `IngestReportOutcome::Duplicate(existing)`, no new row created.
    /// - Counter == 0xFFFFFF: flags terminal anomaly `saturation`.
    /// - Counter regression: if tag exists and `report.counter < last_counter`, flags anomaly `counter_regression`.
    /// - Max-only counter merge: `last_counter = max(last_counter, report.counter)` (no counter_replay check for reports).
    /// - Inserts row into `tap_reports`.
    pub fn ingest_tap_report(
        &mut self,
        report: &TapReportInput,
    ) -> rusqlite::Result<IngestReportOutcome> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // 1. Check for duplicate tap_id
        let existing: Option<TapReportRow> = tx
            .query_row(
                "SELECT tap_id, device_id, uid, counter, decision, reason, time_uncertain, dev_ts, recv_ts, key_version, kind
                 FROM tap_reports WHERE tap_id = ?1",
                params![report.tap_id],
                |r| {
                    Ok(TapReportRow {
                        tap_id: r.get(0)?,
                        device_id: r.get(1)?,
                        uid: r.get(2)?,
                        counter: r.get(3)?,
                        decision: r.get(4)?,
                        reason: r.get(5)?,
                        time_uncertain: r.get(6)?,
                        dev_ts: r.get(7)?,
                        recv_ts: r.get(8)?,
                        key_version: r.get(9)?,
                        kind: r.get(10)?,
                    })
                },
            )
            .optional()?;

        if let Some(row) = existing {
            return Ok(IngestReportOutcome::Duplicate(Box::new(row)));
        }

        // 2. Cross-door duplicate detection (MUST DO #5)
        // If this (uid, counter) was already reported by a DIFFERENT device_id,
        // record an anomaly of kind 'cross_door_duplicate'.
        let prior_device: Option<String> = tx
            .query_row(
                "SELECT device_id FROM tap_reports WHERE uid = ?1 AND counter = ?2 AND device_id != ?3 LIMIT 1",
                params![report.uid, report.counter, report.device_id],
                |r| r.get(0),
            )
            .optional()?;

        if let Some(other_dev) = prior_device {
            tx.execute(
                "INSERT INTO anomalies (ts, device_id, uid, kind, detail)
                 VALUES (?1, ?2, ?3, 'cross_door_duplicate', ?4)",
                params![
                    report.recv_ts,
                    report.device_id,
                    report.uid,
                    format!(
                        "tap_id={}; counter={} previously reported by device_id={}",
                        report.tap_id, report.counter, other_dev
                    ),
                ],
            )?;
        }

        // 3. Check saturation: counter == 0xFFFFFF (16777215)
        if report.counter == 0xFF_FFFF {
            tx.execute(
                "INSERT INTO anomalies (ts, device_id, uid, kind, detail)
                 VALUES (?1, ?2, ?3, 'saturation', ?4)",
                params![
                    report.recv_ts,
                    report.device_id,
                    report.uid,
                    format!("tap_id={}; counter=0xFFFFFF saturated", report.tap_id)
                ],
            )?;
        }

        // 4. Counter check against tags table (if tag exists and CMAC did not fail)
        let is_cmac_fail = matches!(report.reason, Some("cmac_fail" | "bad_cmac"));
        if !is_cmac_fail {
            let tag_counter: Option<i64> = tx
                .query_row(
                    "SELECT last_counter FROM tags WHERE uid = ?1",
                    params![report.uid],
                    |r| r.get(0),
                )
                .optional()?;

            if let Some(last) = tag_counter {
                if report.counter < last {
                    // Counter regression anomaly
                    tx.execute(
                        "INSERT INTO anomalies (ts, device_id, uid, kind, detail)
                         VALUES (?1, ?2, ?3, 'counter_regression', ?4)",
                        params![
                            report.recv_ts,
                            report.device_id,
                            report.uid,
                            format!(
                                "tap_id={}; report_counter={} < last_counter={}",
                                report.tap_id, report.counter, last
                            )
                        ],
                    )?;
                } else if report.counter > last {
                    // Max-only counter merge
                    tx.execute(
                        "UPDATE tags SET last_counter = ?1 WHERE uid = ?2",
                        params![report.counter, report.uid],
                    )?;
                }
            }
        }

        // 5. Insert tap_reports row
        tx.execute(
            "INSERT INTO tap_reports (tap_id, device_id, uid, counter, decision, reason, time_uncertain, dev_ts, recv_ts, key_version, kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                report.tap_id,
                report.device_id,
                report.uid,
                report.counter,
                report.decision,
                report.reason,
                if report.time_uncertain { 1 } else { 0 },
                report.dev_ts,
                report.recv_ts,
                report.key_version,
                report.kind,
            ],
        )?;

        tx.commit()?;
        Ok(IngestReportOutcome::Ingested)
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    // Task 6: Read-only query helpers for admin v2 surfaces (anomalies, tap reports)
    pub fn list_anomalies_filtered(
        &self,
        limit: u32,
        kind: Option<&str>,
        device_id: Option<&str>,
    ) -> rusqlite::Result<Vec<AnomalyRow>> {
        let mut sql = String::from(
            "SELECT id, ts, device_id, uid, kind, detail
             FROM anomalies WHERE 1=1",
        );
        let mut binds: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(k) = kind {
            binds.push(rusqlite::types::Value::Text(k.to_string()));
            sql.push_str(&format!(" AND kind = ?{}", binds.len()));
        }
        if let Some(d) = device_id {
            binds.push(rusqlite::types::Value::Text(d.to_string()));
            sql.push_str(&format!(" AND device_id = ?{}", binds.len()));
        }
        binds.push(rusqlite::types::Value::Integer(i64::from(limit)));
        sql.push_str(&format!(" ORDER BY id DESC LIMIT ?{}", binds.len()));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(binds), |r| {
            Ok(AnomalyRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                device_id: r.get(2)?,
                uid: r.get(3)?,
                kind: r.get(4)?,
                detail: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_tap_reports(
        &self,
        limit: u32,
        device_id: Option<&str>,
        uid: Option<&str>,
    ) -> rusqlite::Result<Vec<TapReportRow>> {
        let mut sql = String::from(
            "SELECT tap_id, device_id, uid, counter, decision, reason, time_uncertain, dev_ts, recv_ts, key_version, kind
             FROM tap_reports WHERE 1=1",
        );
        let mut binds: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(d) = device_id {
            binds.push(rusqlite::types::Value::Text(d.to_string()));
            sql.push_str(&format!(" AND device_id = ?{}", binds.len()));
        }
        if let Some(u) = uid {
            binds.push(rusqlite::types::Value::Text(u.to_string()));
            sql.push_str(&format!(" AND uid = ?{}", binds.len()));
        }
        binds.push(rusqlite::types::Value::Integer(i64::from(limit)));
        sql.push_str(&format!(
            " ORDER BY recv_ts DESC, tap_id DESC LIMIT ?{}",
            binds.len()
        ));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(binds), |r| {
            let tu: i64 = r.get(6)?;
            Ok(TapReportRow {
                tap_id: r.get(0)?,
                device_id: r.get(1)?,
                uid: r.get(2)?,
                counter: r.get(3)?,
                decision: r.get(4)?,
                reason: r.get(5)?,
                time_uncertain: tu != 0,
                dev_ts: r.get(7)?,
                recv_ts: r.get(8)?,
                key_version: r.get(9)?,
                kind: r.get(10)?,
            })
        })?;
        rows.collect()
    }

    pub fn build_full_snapshot(&self) -> rusqlite::Result<(u64, Vec<RosterEntry>)> {
        let roster_gen: u64 = self
            .conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM config WHERE key = 'roster_gen'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0)
            .max(0) as u64;

        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT t.uid, t.key_version, t.last_counter, t.status, t.entry_gen, m.active_until
             FROM tags t
             LEFT JOIN members m ON m.member_key = t.member_key
             WHERE t.status = 'active'
             ORDER BY t.uid",
        )?;

        let mut entries = Vec::new();
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?;

        for row in rows {
            let (uid, key_version, last_counter, status, entry_gen, active_until) = row?;
            let override_kind: Option<String> = self
                .conn
                .query_row(
                    "SELECT kind FROM overrides
                     WHERE (uid = ?1 OR member_key = (SELECT member_key FROM tags WHERE uid = ?1))
                       AND (expires_at IS NULL OR expires_at > ?2)
                     ORDER BY id DESC LIMIT 1",
                    params![uid, now],
                    |r| r.get(0),
                )
                .optional()?;

            let mut flags = 0u8;
            if status != "active" {
                flags |= FLAG_REVOKED;
            }
            if let Some(kind) = override_kind {
                if kind == "ban" {
                    flags |= FLAG_OVERRIDDEN_BAN;
                } else if kind == "allow" {
                    flags |= FLAG_OVERRIDDEN_ALLOW;
                }
            }

            let expiry_epoch = match active_until
                .as_deref()
                .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            {
                Some(dt) => dt.timestamp().max(0) as u32,
                None => {
                    flags |= FLAG_EXPIRY_ABSENT;
                    0
                }
            };

            entries.push(RosterEntry {
                uid: parse_uid_7(&uid),
                counter: last_counter as u32,
                expiry_epoch,
                key_version: key_version as u8,
                entry_gen: entry_gen as u32,
                flags,
            });
        }

        Ok((roster_gen, entries))
    }

    pub fn build_delta_projection(
        &self,
        device_gen: u64,
    ) -> rusqlite::Result<Option<(u64, Vec<RosterEntry>)>> {
        let roster_gen: u64 = self
            .conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM config WHERE key = 'roster_gen'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0)
            .max(0) as u64;

        if device_gen >= roster_gen {
            return Ok(Some((roster_gen, Vec::new())));
        }

        let stats: (Option<i64>, i64) = self.conn.query_row(
            "SELECT MIN(roster_gen), COUNT(*) FROM roster_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let (min_gen, count) = stats;
        if count == 0 {
            return Ok(None);
        }

        let min_gen = min_gen.unwrap_or(1).max(0) as u64;
        if device_gen + 1 < min_gen {
            // Evicted delta history fallback
            return Ok(None);
        }

        let mut stmt = self.conn.prepare(
            "SELECT roster_gen, uid, entry_blob
             FROM roster_events
             WHERE roster_gen > ?1
             ORDER BY roster_gen ASC",
        )?;

        let mut entries_by_uid: std::collections::BTreeMap<String, RosterEntry> =
            std::collections::BTreeMap::new();

        let rows = stmt.query_map(params![device_gen as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;

        for row in rows {
            let (_gen, uid, blob) = row?;
            if let Ok(bytes) = hex::decode(&blob) {
                if bytes.len() == ROSTER_ENTRY_SIZE {
                    let mut b = [0u8; ROSTER_ENTRY_SIZE];
                    b.copy_from_slice(&bytes);
                    entries_by_uid.insert(uid, RosterEntry::decode(&b));
                }
            }
        }

        let entries: Vec<_> = entries_by_uid.into_values().collect();
        Ok(Some((roster_gen, entries)))
    }

    pub fn prune_roster_events(&mut self) -> rusqlite::Result<usize> {
        let deleted_old = self.conn.execute(
            "DELETE FROM roster_events WHERE ts < datetime('now', '-30 days')",
            [],
        )?;
        let deleted_excess = self.conn.execute(
            "DELETE FROM roster_events WHERE rowid NOT IN (
                SELECT rowid FROM roster_events ORDER BY roster_gen DESC, rowid DESC LIMIT 10000
            )",
            [],
        )?;
        Ok(deleted_old + deleted_excess)
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

/// A live provisioning job as shown in the admin UI's pending list (T6).
/// An empty `uid` is a wildcard job whose tag has not been tapped yet.
pub type PendingJobRow = MemberJobStatus;

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberJobStatus {
    pub job_id: String,
    pub uid: String,
    pub member_key: String,
    pub device_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub outcome: Option<String>, // "enrolled", "failed", "cancelled", etc.
    pub reason: Option<String>,
}

#[derive(Debug)]
pub enum JobTake {
    Taken(JobRow),
    AlreadyConsumed(JobRow),
    Expired(JobRow),
    NotFound,
}

/// Outcome of `claim_job`. `Claimed` means the caller may deliver the key;
/// the other variants carry the job row (when it exists) for auditing.
#[derive(Debug)]
pub enum JobClaim {
    Claimed(JobRow),
    UidMismatch(JobRow),
    Consumed(JobRow),
    Expired(JobRow),
    NotFound,
}

/// RFC3339 expiry check shared by `take_job` and `claim_job`. An unparseable
/// expiry is treated as expired (fail-safe: no delivery).
fn job_expired(expires_at: &str, now: &str) -> bool {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(dt) => {
            let now_dt = chrono::DateTime::parse_from_rfc3339(now)
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            dt.with_timezone(&chrono::Utc) <= now_dt
        }
        Err(_) => true,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TagInfo {
    pub uid: String,
    pub member_key: String,
    pub status: String,
    pub key_version: i64,
    pub last_counter: i64,
    pub enrolled_at: String,
    pub entry_gen: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberInfo {
    pub member_key: String,
    pub display_name: Option<String>,
    pub active_until: String,
    pub source: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub role: String,
    pub offline_verify: bool,
    pub presence: String,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditInfo {
    pub id: i64,
    pub ts: String,
    pub device_id: Option<String>,
    pub uid: Option<String>,
    pub counter: Option<i64>,
    pub decision: String,
    pub reason: String,
    pub member_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TapReportRow {
    pub tap_id: String,
    pub device_id: String,
    pub uid: String,
    pub counter: i64,
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub time_uncertain: bool,
    pub dev_ts: Option<String>,
    pub recv_ts: String,
    pub key_version: Option<i64>,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub struct TapReportInput<'a> {
    pub tap_id: &'a str,
    pub device_id: &'a str,
    pub uid: &'a str,
    pub counter: i64,
    pub decision: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub time_uncertain: bool,
    pub dev_ts: Option<&'a str>,
    pub recv_ts: &'a str,
    pub key_version: Option<i64>,
    pub kind: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestReportOutcome {
    Ingested,
    Duplicate(Box<TapReportRow>),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnomalyRow {
    pub id: i64,
    pub ts: String,
    pub device_id: Option<String>,
    pub uid: Option<String>,
    pub kind: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OverrideInfo {
    pub id: i64,
    pub member_key: Option<String>,
    pub uid: Option<String>,
    pub kind: String,
    pub expires_at: Option<String>,
    pub note: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStateInfo {
    pub last_success: Option<String>,
    pub last_attempt: Option<String>,
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_mem() -> Store {
        Store::open(":memory:").expect("open :memory: store")
    }

    fn status_of(store: &Store, uid: &str) -> String {
        store
            .conn
            .query_row(
                "SELECT status FROM tags WHERE uid = ?1",
                params![uid],
                |r| r.get(0),
            )
            .expect("tag row exists")
    }

    #[test]
    fn enrolling_new_tag_revokes_members_previous_active_tag() {
        let mut store = open_mem();
        store
            .enroll_job_tag("uid-old", "member-a", 1, 5, "2026-10-15T00:00:00Z")
            .unwrap();
        store
            .enroll_job_tag("uid-new", "member-a", 1, 1, "2026-10-15T01:00:00Z")
            .unwrap();
        assert_eq!(status_of(&store, "uid-old"), "revoked");
        assert_eq!(status_of(&store, "uid-new"), "active");
    }

    #[test]
    fn reenrolling_same_uid_keeps_it_active_and_revokes_others() {
        // Found-card flow: the lost tag was replaced (revoked), then found
        // and re-provisioned under supervision — it comes back, the current
        // tag retires.
        let mut store = open_mem();
        store
            .enroll_job_tag("uid-lost", "member-a", 1, 9, "2026-10-14T00:00:00Z")
            .unwrap();
        store
            .enroll_job_tag("uid-cur", "member-a", 1, 1, "2026-10-15T00:00:00Z")
            .unwrap();
        assert_eq!(status_of(&store, "uid-lost"), "revoked");

        store
            .enroll_job_tag("uid-lost", "member-a", 1, 12, "2026-10-16T00:00:00Z")
            .unwrap();
        assert_eq!(status_of(&store, "uid-lost"), "active");
        assert_eq!(status_of(&store, "uid-cur"), "revoked");
    }

    #[test]
    fn admin_enroll_path_enforces_replacement_too() {
        let mut store = open_mem();
        store
            .enroll_tag("uid-a", "member-a", 1, "2026-10-15T00:00:00Z")
            .unwrap();
        store
            .enroll_tag("uid-b", "member-a", 1, "2026-10-15T01:00:00Z")
            .unwrap();
        assert_eq!(status_of(&store, "uid-a"), "revoked");
        assert_eq!(status_of(&store, "uid-b"), "active");
    }

    #[test]
    fn second_active_tag_per_member_is_unrepresentable() {
        // The invariant lives in the storage layer: no code path, present or
        // future, can create a concurrently-valid second tag for a member.
        let mut store = open_mem();
        store
            .enroll_job_tag("uid-a", "member-a", 1, 1, "2026-10-15T00:00:00Z")
            .unwrap();
        let raw = conn_raw_insert_second_active(&store, "member-a");
        assert!(raw.is_err(), "unique partial index must reject it");
    }

    fn conn_raw_insert_second_active(store: &Store, member_key: &str) -> rusqlite::Result<usize> {
        store.conn.execute(
            "INSERT INTO tags (uid, member_key, key_version, last_counter, status, enrolled_at)
             VALUES ('uid-rogue', ?1, 1, 0, 'active', '2026-10-15T02:00:00Z')",
            params![member_key],
        )
    }

    #[test]
    fn migration_retires_preexisting_concurrently_active_tags() {
        // Tags enrolled before the policy existed: the schema migration must
        // retire all but the newest-enrolled active tag per member.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tags (
                uid TEXT PRIMARY KEY,
                member_key TEXT NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                last_counter INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                note TEXT,
                enrolled_at TEXT NOT NULL
            );
            INSERT INTO tags (uid, member_key, status, enrolled_at) VALUES
                ('uid-oldest', 'member-a', 'active', '2026-10-07T00:00:00Z'),
                ('uid-middle', 'member-a', 'active', '2026-10-15T01:32:48Z'),
                ('uid-newest', 'member-a', 'active', '2026-10-15T01:35:27Z'),
                ('uid-other',  'member-b', 'active', '2026-10-01T00:00:00Z');",
        )
        .unwrap();

        Store::apply_schema_to(&conn).unwrap();

        let status = |uid: &str| -> String {
            conn.query_row(
                "SELECT status FROM tags WHERE uid = ?1",
                params![uid],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(status("uid-newest"), "active");
        assert_eq!(status("uid-oldest"), "revoked");
        assert_eq!(status("uid-middle"), "revoked");
        assert_eq!(status("uid-other"), "active", "other members untouched");
    }
}
