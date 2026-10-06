#[path = "../src/store.rs"]
pub mod store;

use std::sync::Arc;
use std::thread;
use store::{AccessDecision, Store, TapOutcome};
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

    // 2. Unknown member
    assert_eq!(
        store.effective_access(uid, ts).unwrap(),
        AccessDecision::Denied("unknown_member".to_string())
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
        AccessDecision::Denied("member_inactive".to_string())
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
        AccessDecision::Denied("member_inactive".to_string())
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
