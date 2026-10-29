use access_control_verifier::store::{self, AccessDecision, JobClaim, Store, TapOutcome};
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

#[test]
fn test_schema_idempotency() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    // First open
    let _store1 = Store::open(&db_path).expect("Failed to open store first time");

    // Second open (should not fail, schema applies idempotently)
    let _store2 = Store::open(&db_path).expect("Failed to open store second time");
}

#[test]
fn test_enroll_tap_and_counter_replay() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    let uid = "04123456789ABC";
    let ts = "2026-10-06T10:00:00Z";

    // 1. Unknown tag
    assert_eq!(
        store
            .record_tap(uid, 1, Some("door1"), ts, AccessDecision::Granted)
            .unwrap(),
        TapOutcome::Denied("unknown_tag".to_string())
    );

    // 2. Enroll
    store.enroll_tag(uid, "member123", 1, ts).unwrap();

    // 3. Valid tap
    assert_eq!(
        store
            .record_tap(uid, 10, Some("door1"), ts, AccessDecision::Granted)
            .unwrap(),
        TapOutcome::Granted
    );

    // 4. Counter replay (same counter)
    assert_eq!(
        store
            .record_tap(uid, 10, Some("door1"), ts, AccessDecision::Granted)
            .unwrap(),
        TapOutcome::Denied("counter_replay".to_string())
    );

    // 5. Counter replay (lower counter)
    assert_eq!(
        store
            .record_tap(uid, 5, Some("door1"), ts, AccessDecision::Granted)
            .unwrap(),
        TapOutcome::Denied("counter_replay".to_string())
    );

    // 6. Valid higher counter, but access denied logically
    assert_eq!(
        store
            .record_tap(
                uid,
                15,
                Some("door1"),
                ts,
                AccessDecision::Denied("member_inactive".to_string())
            )
            .unwrap(),
        TapOutcome::Denied("member_inactive".to_string())
    );
}

#[test]
fn test_concurrency_lost_updates() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    // Enroll the tag first
    {
        let mut store = Store::open(&db_path).unwrap();
        store
            .enroll_tag("concurrent_uid", "member_x", 1, "2026-10-06T10:00:00Z")
            .unwrap();
    }

    let num_threads = 20;
    let mut handles = vec![];

    let global_counter = Arc::new(std::sync::atomic::AtomicI64::new(1));

    for i in 1..=num_threads {
        let db_path = db_path.clone();
        let counter_ref = Arc::clone(&global_counter);
        handles.push(thread::spawn(move || {
            let mut store = Store::open(&db_path).unwrap();
            let ts = format!("2026-10-06T10:00:{:02}Z", i);
            let outcome;
            loop {
                let current_c = counter_ref.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let res = store
                    .record_tap(
                        "concurrent_uid",
                        current_c,
                        Some("door1"),
                        &ts,
                        AccessDecision::Granted,
                    )
                    .unwrap();
                if res == TapOutcome::Granted {
                    outcome = res;
                    break;
                }
            }
            assert_eq!(outcome, TapOutcome::Granted);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Check final state
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    // 1. Counter should be exactly `num_threads`
    let final_counter: i64 = conn
        .query_row(
            "SELECT last_counter FROM tags WHERE uid = 'concurrent_uid'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(final_counter >= num_threads as i64);

    // 2. Audit log should have exactly `num_threads` entries for this uid
    let audit_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE uid = 'concurrent_uid' AND decision = 'granted'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(audit_count, num_threads as i64);
}

#[test]
fn test_effective_access() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    let uid = "04123456789ABC";
    let member_key = "member123";
    let ts = "2026-10-06T10:00:00Z";

    // 1. Unknown tag
    assert_eq!(
        store.effective_access(uid, ts).unwrap(),
        AccessDecision::Denied("unknown_tag".to_string())
    );

    store.enroll_tag(uid, member_key, 1, ts).unwrap();

    // 2. Roster row missing (sync removed the member) — the membership
    // lapsed; the person is an ex-member now.
    assert_eq!(
        store.effective_access(uid, ts).unwrap(),
        AccessDecision::Denied("expired_membership".to_string())
    );

    // Insert member
    // Using rusqlite directly to manipulate for testing
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "INSERT INTO members (member_key, display_name, active_until) VALUES (?1, ?2, ?3)",
        rusqlite::params![member_key, "Alice", "2026-10-05T10:00:00Z"], // expired by 1 day
    )
    .unwrap();

    // 3. Grace period (active_until is 1 day ago, grace is 5 days) -> Granted
    assert_eq!(
        store.effective_access(uid, ts).unwrap(),
        AccessDecision::Granted
    );

    // 4. Over grace period
    assert_eq!(
        store.effective_access(uid, "2026-10-15T10:00:00Z").unwrap(),
        AccessDecision::Denied("expired_membership".to_string())
    );

    // 5. Override allow (even if over grace)
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "INSERT INTO overrides (member_key, kind, created_at, expires_at) VALUES (?1, 'allow', ?2, ?3)",
        rusqlite::params![member_key, ts, "2026-10-20T10:00:00Z"],
    ).unwrap();

    assert_eq!(
        store.effective_access(uid, "2026-10-15T10:00:00Z").unwrap(),
        AccessDecision::Granted
    );

    // 6. Expired override allow
    assert_eq!(
        store.effective_access(uid, "2026-10-21T10:00:00Z").unwrap(),
        AccessDecision::Denied("expired_membership".to_string())
    );

    // 7. Override ban (takes precedence over active member)
    conn.execute(
        "UPDATE members SET active_until = '2026-12-01T10:00:00Z' WHERE member_key = ?1",
        rusqlite::params![member_key],
    )
    .unwrap();

    assert_eq!(
        store.effective_access(uid, ts).unwrap(),
        AccessDecision::Granted
    ); // normal active

    conn.execute(
        "INSERT INTO overrides (member_key, kind, created_at) VALUES (?1, 'ban', ?2)",
        rusqlite::params![member_key, ts],
    )
    .unwrap();

    assert_eq!(
        store.effective_access(uid, ts).unwrap(),
        AccessDecision::Denied("override_ban".to_string())
    );
}

#[test]
fn test_presence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    store
        .set_presence("door1", true, "2026-10-06T10:00:00Z")
        .unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let (presence, role): (String, String) = conn
        .query_row(
            "SELECT presence, role FROM devices WHERE device_id = 'door1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(presence, "online");
    assert_eq!(role, "gate");
}

#[test]
fn test_claim_job_wildcard_binds_uid() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    let now = "2026-10-06T10:00:00Z";
    let expires = "2026-10-06T10:02:00Z";
    let job_id = store
        .create_job("", "m1", "writer-01", now, expires)
        .unwrap();

    // First claim binds the uid.
    match store.claim_job(&job_id, "04010203040506", now).unwrap() {
        JobClaim::Claimed(job) => assert_eq!(job.uid, "04010203040506"),
        other => panic!("expected Claimed, got {other:?}"),
    }

    // Re-claim with the same uid is idempotent.
    match store.claim_job(&job_id, "04010203040506", now).unwrap() {
        JobClaim::Claimed(job) => assert_eq!(job.uid, "04010203040506"),
        other => panic!("expected Claimed, got {other:?}"),
    }

    // A different uid is refused once the job is bound.
    match store.claim_job(&job_id, "0405060708090a", now).unwrap() {
        JobClaim::UidMismatch(job) => assert_eq!(job.uid, "04010203040506"),
        other => panic!("expected UidMismatch, got {other:?}"),
    }
}

#[test]
fn test_claim_job_fixed_uid_and_states() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    let now = "2026-10-06T10:00:00Z";
    let expires = "2026-10-06T10:02:00Z";
    let job_id = store
        .create_job("04010203040506", "m1", "writer-01", now, expires)
        .unwrap();

    // Wrong uid on a fixed-uid job ⇒ UidMismatch.
    match store.claim_job(&job_id, "0405060708090a", now).unwrap() {
        JobClaim::UidMismatch(_) => {}
        other => panic!("expected UidMismatch, got {other:?}"),
    }

    // Matching uid ⇒ Claimed.
    match store.claim_job(&job_id, "04010203040506", now).unwrap() {
        JobClaim::Claimed(_) => {}
        other => panic!("expected Claimed, got {other:?}"),
    }

    // Unknown job.
    match store
        .claim_job("00000000000000000000000000000000", "04010203040506", now)
        .unwrap()
    {
        JobClaim::NotFound => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Past the TTL ⇒ Expired.
    match store
        .claim_job(&job_id, "04010203040506", "2026-10-06T10:05:00Z")
        .unwrap()
    {
        JobClaim::Expired(_) => {}
        other => panic!("expected Expired, got {other:?}"),
    }
}

#[test]
fn test_fail_job_marks_consumed_and_audits() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    let now = "2026-10-06T10:00:00Z";
    let expires = "2026-10-06T10:02:00Z";
    let job_id = store
        .create_job("04010203040506", "m1", "writer-01", now, expires)
        .unwrap();

    assert!(store.fail_job(&job_id, now, "provision_failed").unwrap());

    // The failed job is now consumed; a later claim observes Consumed.
    match store.claim_job(&job_id, "04010203040506", now).unwrap() {
        JobClaim::Consumed(_) => {}
        other => panic!("expected Consumed, got {other:?}"),
    }

    // Unknown job ⇒ false.
    assert!(!store
        .fail_job("00000000000000000000000000000000", now, "x")
        .unwrap());

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let audits: (i64, Option<String>) = conn
        .query_row(
            "SELECT COUNT(*), member_key FROM audit_log WHERE reason = 'job_failed' AND decision = 'denied'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(audits.0, 1);
    assert_eq!(audits.1.as_deref(), Some("m1"));
}

#[test]
fn test_set_device_role() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    store.upsert_device("reader-01", "gate", false).unwrap();
    assert_eq!(
        store.device_role("reader-01").unwrap().as_deref(),
        Some("gate")
    );

    assert!(store.set_device_role("reader-01", "both").unwrap());
    assert_eq!(
        store.device_role("reader-01").unwrap().as_deref(),
        Some("both")
    );

    // Invalid role and unknown device both return false without mutating.
    assert!(!store.set_device_role("reader-01", "admin").unwrap());
    assert_eq!(
        store.device_role("reader-01").unwrap().as_deref(),
        Some("both")
    );
    assert!(!store.set_device_role("ghost", "writer").unwrap());
}

#[test]
fn test_additive_schema_and_entry_gen_backfill() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("preexisting.db");

    // Simulate an older DB created before tags.entry_gen and audit_log.member_key existed
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
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
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                device_id TEXT,
                uid TEXT,
                counter INTEGER,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            INSERT INTO tags (uid, member_key, enrolled_at) VALUES ('pre_uid_1', 'member_old', '2026-01-01T00:00:00Z');
            INSERT INTO audit_log (ts, device_id, uid, decision, reason) VALUES ('2026-01-01T00:00:00Z', 'dev1', 'pre_uid_1', 'granted', 'ok');",
        ).unwrap();
    }

    // Now open Store on that preexisting db, which runs apply_schema
    let store = Store::open(&db_path).unwrap();

    // Verify config default roster_gen = 0
    assert_eq!(
        store.get_config("roster_gen").unwrap().as_deref(),
        Some("0")
    );

    // Verify existing tag row received default entry_gen = 1
    let tag = store.tag_by_uid("pre_uid_1").unwrap().expect("tag found");
    assert_eq!(tag.entry_gen, 1);

    // Verify audit_log row has null member_key and can be read by list_audit
    let audits = store.list_audit(10, None, None).unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].member_key, None);
}

#[test]
fn test_ingest_tap_report_idempotency_and_anomalies() {
    use store::{IngestReportOutcome, TapReportInput};

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = Store::open(&db_path).unwrap();

    // Enroll a tag with counter 100
    store
        .enroll_job_tag("04010203040506", "member_1", 1, 100, "2026-10-28T12:00:00Z")
        .unwrap();

    // 1. Valid forward tap report
    let rep1 = TapReportInput {
        tap_id: "door1:1",
        device_id: "door1",
        uid: "04010203040506",
        counter: 105,
        decision: Some("granted"),
        reason: Some("granted"),
        time_uncertain: false,
        dev_ts: Some("2026-10-28T12:05:00Z"),
        recv_ts: "2026-10-28T12:05:01Z",
        key_version: Some(1),
        kind: "report",
    };
    let outcome1 = store.ingest_tap_report(&rep1).unwrap();
    assert_eq!(outcome1, IngestReportOutcome::Ingested);

    // Counter merged to 105
    let tag = store.tag_by_uid("04010203040506").unwrap().unwrap();
    assert_eq!(tag.last_counter, 105);

    // 2. Duplicate tap_id (door1:1) returns Duplicate and DOES NOT mutate
    let outcome2 = store.ingest_tap_report(&rep1).unwrap();
    match outcome2 {
        IngestReportOutcome::Duplicate(row) => {
            assert_eq!(row.tap_id, "door1:1");
            assert_eq!(row.counter, 105);
            assert_eq!(row.kind, "report");
        }
        _ => panic!("expected duplicate tap outcome"),
    }

    // 3. Counter regression (e.g., door1:2 reports counter 102 < 105)
    let rep_regress = TapReportInput {
        tap_id: "door1:2",
        device_id: "door1",
        uid: "04010203040506",
        counter: 102,
        decision: Some("granted"),
        reason: Some("granted"),
        time_uncertain: false,
        dev_ts: Some("2026-10-28T12:06:00Z"),
        recv_ts: "2026-10-28T12:06:01Z",
        key_version: Some(1),
        kind: "report",
    };
    let outcome_regress = store.ingest_tap_report(&rep_regress).unwrap();
    assert_eq!(outcome_regress, IngestReportOutcome::Ingested);

    // Counter did NOT regress on the tag
    let tag = store.tag_by_uid("04010203040506").unwrap().unwrap();
    assert_eq!(tag.last_counter, 105);

    // Check anomaly logged for counter_regression
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let anomaly_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM anomalies WHERE kind = 'counter_regression' AND uid = '04010203040506'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(anomaly_count, 1);

    // 4. Counter saturation (counter == 0xFFFFFF = 16777215)
    let rep_sat = TapReportInput {
        tap_id: "door1:3",
        device_id: "door1",
        uid: "04010203040506",
        counter: 0xFF_FFFF,
        decision: Some("denied"),
        reason: Some("counter_saturated"),
        time_uncertain: false,
        dev_ts: Some("2026-10-28T12:07:00Z"),
        recv_ts: "2026-10-28T12:07:01Z",
        key_version: Some(1),
        kind: "report",
    };
    let outcome_sat = store.ingest_tap_report(&rep_sat).unwrap();
    assert_eq!(outcome_sat, IngestReportOutcome::Ingested);

    let sat_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM anomalies WHERE kind = 'saturation' AND uid = '04010203040506'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sat_count, 1);
}

#[test]
fn test_policy_changes_bump_entry_gen_and_roster_events() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("bump_test.db");
    let mut store = Store::open(&db_path).unwrap();

    // 1. Initial roster_gen is 0
    assert_eq!(
        store.get_config("roster_gen").unwrap().as_deref(),
        Some("0")
    );

    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m1', 'Member One', '2027-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

    // 2. Enroll first tag => entry_gen = 1, roster_gen = 1, 1 roster_event
    let ts1 = "2026-10-28T10:00:00Z";
    store.enroll_tag("04112233445566", "m1", 1, ts1).unwrap();

    let tag1 = store.tag_by_uid("04112233445566").unwrap().unwrap();
    assert_eq!(tag1.entry_gen, 1);
    assert_eq!(tag1.status, "active");
    assert_eq!(
        store.get_config("roster_gen").unwrap().as_deref(),
        Some("1")
    );

    // Check roster_events has 1 row with roster_gen = 1
    let (ev_count, ev_blob): (i64, String) = store
        .conn_mut()
        .query_row(
            "SELECT COUNT(*), entry_blob FROM roster_events WHERE uid = '04112233445566'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(ev_count, 1);
    let bytes = hex::decode(&ev_blob).unwrap();
    let entry =
        access_control_verifier::sync_projection::RosterEntry::decode(&bytes.try_into().unwrap());
    assert_eq!(entry.entry_gen, 1);
    assert_eq!(entry.flags, 0); // active, valid expiry => flags 0

    // 3. Enroll second tag for same member => replaces tag1 (revokes tag1)
    // tag1 gets status='revoked', entry_gen bumped to 2, roster_gen becomes 2.
    // tag2 is enrolled, entry_gen = 1, roster_gen becomes 3.
    let ts2 = "2026-10-28T10:05:00Z";
    store.enroll_tag("04aabbccddeeff", "m1", 1, ts2).unwrap();

    let tag1_after = store.tag_by_uid("04112233445566").unwrap().unwrap();
    assert_eq!(tag1_after.status, "revoked");
    assert_eq!(tag1_after.entry_gen, 2);

    let tag2 = store.tag_by_uid("04aabbccddeeff").unwrap().unwrap();
    assert_eq!(tag2.status, "active");
    assert_eq!(tag2.entry_gen, 1);

    assert_eq!(
        store.get_config("roster_gen").unwrap().as_deref(),
        Some("3")
    );

    // Total roster events is now 3
    let total_ev: i64 = store
        .conn_mut()
        .query_row("SELECT COUNT(*) FROM roster_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total_ev, 3);

    // 4. Revoke tag2 => status='revoked', entry_gen bumped to 2, roster_gen becomes 4
    store.revoke_tag("04aabbccddeeff").unwrap();
    let tag2_after = store.tag_by_uid("04aabbccddeeff").unwrap().unwrap();
    assert_eq!(tag2_after.status, "revoked");
    assert_eq!(tag2_after.entry_gen, 2);
    assert_eq!(
        store.get_config("roster_gen").unwrap().as_deref(),
        Some("4")
    );

    // 5. Revoking again does NOT bump (idempotent, no policy change)
    store.revoke_tag("04aabbccddeeff").unwrap();
    let tag2_same = store.tag_by_uid("04aabbccddeeff").unwrap().unwrap();
    assert_eq!(tag2_same.entry_gen, 2);
    assert_eq!(
        store.get_config("roster_gen").unwrap().as_deref(),
        Some("4")
    );
}

#[test]
fn test_counter_only_changes_never_bump_generations() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("counter_no_bump.db");
    let mut store = Store::open(&db_path).unwrap();

    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m1', 'Member One', '2027-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

    let ts = "2026-10-28T10:00:00Z";
    store.enroll_tag("04010203040506", "m1", 1, ts).unwrap();

    let gen_before = store.get_config("roster_gen").unwrap().unwrap();
    let tag_before = store.tag_by_uid("04010203040506").unwrap().unwrap();
    assert_eq!(tag_before.entry_gen, 1);
    assert_eq!(tag_before.last_counter, 0);

    let ev_count_before: i64 = store
        .conn_mut()
        .query_row("SELECT COUNT(*) FROM roster_events", [], |r| r.get(0))
        .unwrap();

    // 1. Advance counter via record_tap
    let outcome = store
        .record_tap(
            "04010203040506",
            50,
            Some("door1"),
            "2026-10-28T10:01:00Z",
            AccessDecision::Granted,
        )
        .unwrap();
    assert_eq!(outcome, TapOutcome::Granted);

    let tag_after_tap = store.tag_by_uid("04010203040506").unwrap().unwrap();
    assert_eq!(tag_after_tap.last_counter, 50);
    assert_eq!(tag_after_tap.entry_gen, 1, "entry_gen must NOT bump on tap");

    let gen_after_tap = store.get_config("roster_gen").unwrap().unwrap();
    assert_eq!(gen_before, gen_after_tap, "roster_gen must NOT bump on tap");

    let ev_count_after_tap: i64 = store
        .conn_mut()
        .query_row("SELECT COUNT(*) FROM roster_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        ev_count_before, ev_count_after_tap,
        "roster_events count must NOT increase on tap"
    );

    // 2. Advance counter via ingest_tap_report
    use store::TapReportInput;
    let rep = TapReportInput {
        tap_id: "door1:100",
        device_id: "door1",
        uid: "04010203040506",
        counter: 60,
        decision: Some("granted"),
        reason: Some("granted"),
        time_uncertain: false,
        dev_ts: None,
        recv_ts: "2026-10-28T10:02:00Z",
        key_version: Some(1),
        kind: "report",
    };
    store.ingest_tap_report(&rep).unwrap();

    let tag_after_report = store.tag_by_uid("04010203040506").unwrap().unwrap();
    assert_eq!(tag_after_report.last_counter, 60);
    assert_eq!(
        tag_after_report.entry_gen, 1,
        "entry_gen must NOT bump on report counter advance"
    );

    let gen_after_report = store.get_config("roster_gen").unwrap().unwrap();
    assert_eq!(
        gen_before, gen_after_report,
        "roster_gen must NOT bump on report counter advance"
    );

    let ev_count_after_report: i64 = store
        .conn_mut()
        .query_row("SELECT COUNT(*) FROM roster_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        ev_count_before, ev_count_after_report,
        "roster_events count must NOT increase on report counter advance"
    );
}

#[test]
fn test_projections_and_prune() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("proj_test.db");
    let mut store = Store::open(&db_path).unwrap();

    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m1', 'Member One', '2027-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

    let ts = "2026-10-28T10:00:00Z";
    store.enroll_tag("04010203040506", "m1", 1, ts).unwrap();

    // Full snapshot
    let (gen, full_entries) = store.build_full_snapshot().unwrap();
    assert_eq!(gen, 1);
    assert_eq!(full_entries.len(), 1);
    assert_eq!(
        full_entries[0].uid,
        [0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    );
    assert_eq!(full_entries[0].entry_gen, 1);

    // Delta since gen 0
    let delta = store.build_delta_projection(0).unwrap();
    assert!(delta.is_some());
    let (d_gen, d_entries) = delta.unwrap();
    assert_eq!(d_gen, 1);
    assert_eq!(d_entries.len(), 1);

    // Delta since gen 1 (up to date)
    let delta_up_to_date = store.build_delta_projection(1).unwrap();
    assert_eq!(delta_up_to_date, Some((1, Vec::new())));

    // Evicted fallback test: manually simulate evicted roster_events
    store
        .conn_mut()
        .execute("DELETE FROM roster_events", [])
        .unwrap();
    let delta_evicted = store.build_delta_projection(0).unwrap();
    assert_eq!(
        delta_evicted, None,
        "empty events forces full snapshot fallback"
    );

    // Prune test: insert an event with old timestamp (>30 days ago)
    store
        .conn_mut()
        .execute(
            "INSERT INTO roster_events (roster_gen, uid, entry_blob, ts)
             VALUES (1, '04010203040506', '00', datetime('now', '-35 days'))",
            [],
        )
        .unwrap();
    let pruned = store.prune_roster_events().unwrap();
    assert_eq!(pruned, 1);
}
