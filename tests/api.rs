use access_control_verifier::api::{AppState, DecisionSink, NoopSink};
use access_control_verifier::crypto::{cmac_for, Key, TapCounter, Uid};
use access_control_verifier::store::Store;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
use tower::ServiceExt;

const MASTER_HEX: &str = "000102030405060708090a0b0c0d0e0f";
const SECRET: &str = "test-emqx-shared-secret";
const DOOR: &str = "door1";

const UID_ACTIVE: &str = "04010203040506";
const UID_EXPIRED: &str = "04111111111111";
const UID_BANNED: &str = "04222222222222";
const UID_REVOKED: &str = "04333333333333";
const UID_NO_MEMBER: &str = "04444444444444";
const UID_UNENROLLED: &str = "04999999999999";

#[derive(Clone, Default)]
struct TestSink {
    records: Arc<Mutex<Vec<(String, bool, String)>>>,
}

impl TestSink {
    fn pop(&self) -> Option<(String, bool, String)> {
        self.records.lock().expect("sink lock").pop()
    }

    fn len(&self) -> usize {
        self.records.lock().expect("sink lock").len()
    }
}

impl DecisionSink for TestSink {
    fn publish_cmd(&self, reader: &str, grant: bool, reason: &str) {
        self.records.lock().expect("sink lock").push((
            reader.to_string(),
            grant,
            reason.to_string(),
        ));
    }
}

struct Fixture {
    app: axum::Router,
    store: Arc<Mutex<Store>>,
    sink: TestSink,
    _db: NamedTempFile,
}

fn build(sink: Arc<dyn DecisionSink>) -> (axum::Router, Arc<Mutex<Store>>, NamedTempFile) {
    let db = NamedTempFile::new().expect("temp db file");
    let mut store = Store::open(db.path()).expect("store opens");
    let now = chrono::Utc::now().to_rfc3339();

    // Active member whose tag should grant.
    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m1', 'Test Member', datetime('now', '+10 days'))",
            [],
        )
        .expect("insert m1");
    store
        .enroll_tag(UID_ACTIVE, "m1", 1, &now)
        .expect("enroll active tag");

    // Expired member.
    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m2', 'Expired Member', datetime('now', '-20 days'))",
            [],
        )
        .expect("insert m2");
    store
        .enroll_tag(UID_EXPIRED, "m2", 1, &now)
        .expect("enroll expired tag");

    // Banned member (override kind=ban).
    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m3', 'Banned Member', datetime('now', '+10 days'))",
            [],
        )
        .expect("insert m3");
    store
        .enroll_tag(UID_BANNED, "m3", 1, &now)
        .expect("enroll banned tag");
    store
        .conn_mut()
        .execute(
            "INSERT INTO overrides (member_key, kind, created_at)
             VALUES ('m3', 'ban', strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            [],
        )
        .expect("insert ban override");

    // Revoked tag -> store decision tag_inactive.
    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m4', 'Revoked Tag Member', datetime('now', '+10 days'))",
            [],
        )
        .expect("insert m4");
    store
        .enroll_tag(UID_REVOKED, "m4", 1, &now)
        .expect("enroll revoked tag");
    store.revoke_tag(UID_REVOKED).expect("revoke tag");

    // Tag bound to a member that does not exist -> store decision unknown_member.
    store
        .enroll_tag(UID_NO_MEMBER, "ghost", 1, &now)
        .expect("enroll orphan tag");

    let master = Key::from_hex(MASTER_HEX).expect("master key hex");
    let store = Arc::new(Mutex::new(store));
    let state = AppState {
        store: Arc::clone(&store),
        master,
        secret: SECRET.to_string(),
        sink,
    };
    (access_control_verifier::app(state), store, db)
}

fn setup() -> Fixture {
    let sink = TestSink::default();
    let (app, store, db) = build(Arc::new(sink.clone()));
    Fixture {
        app,
        store,
        sink,
        _db: db,
    }
}

fn cmac_hex(_f: &Fixture, uid_hex: &str, counter: u32) -> String {
    let master = Key::from_hex(MASTER_HEX).expect("master key hex");
    let uid = Uid::from_hex(uid_hex).expect("uid hex");
    let tap_counter = TapCounter::from_u32(counter);
    hex::encode(cmac_for(&master, &uid, &tap_counter).0)
}

fn payload(uid_hex: &str, counter: u64, cmac_hex: &str) -> Value {
    json!({ "reader": DOOR, "uid": uid_hex, "counter": counter, "cmac": cmac_hex })
}

async fn send(app: &axum::Router, secret: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/auth")
        .header("content-type", "application/json");
    if let Some(s) = secret {
        builder = builder.header("x-emqx-secret", s);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .expect("request dispatches");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let value = serde_json::from_slice(&bytes).expect("response body is JSON");
    (status, value)
}

fn last_counter(f: &Fixture, uid: &str) -> i64 {
    f.store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT last_counter FROM tags WHERE uid = ?1",
            rusqlite::params![uid],
            |row| row.get(0),
        )
        .expect("counter row exists")
}

fn audit_count(f: &Fixture, uid: &str, reason: &str) -> i64 {
    f.store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE uid = ?1 AND reason = ?2",
            rusqlite::params![uid, reason],
            |row| row.get(0),
        )
        .expect("audit query runs")
}

#[tokio::test]
async fn grants_when_cmac_counter_and_membership_are_valid() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_ACTIVE, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_ACTIVE, 1, &cmac)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": true, "reason": "ok", "name": "Test Member", "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), true, "ok".to_string()))
    );
    assert_eq!(last_counter(&f, UID_ACTIVE), 1);
    assert_eq!(audit_count(&f, UID_ACTIVE, "ok"), 0);
    assert_eq!(
        audit_count(&f, UID_ACTIVE, ""),
        1,
        "granted row carries empty reason"
    );
}

#[tokio::test]
async fn denies_unknown_tag_with_no_counter_state() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_UNENROLLED, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_UNENROLLED, 1, &cmac)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": false, "reason": "unknown_tag", "name": null, "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), false, "unknown_tag".to_string()))
    );
    assert_eq!(audit_count(&f, UID_UNENROLLED, "unknown_tag"), 1);
    // No tags row exists for this uid, hence no counter to advance.
    let rows: i64 = f
        .store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT COUNT(*) FROM tags WHERE uid = ?1",
            rusqlite::params![UID_UNENROLLED],
            |row| row.get(0),
        )
        .expect("count query");
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn denies_bad_cmac_without_advancing_counter() {
    let f = setup();
    // CMAC proves counter 1 while the request claims counter 2.
    let cmac = cmac_hex(&f, UID_ACTIVE, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_ACTIVE, 2, &cmac)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": false, "reason": "bad_cmac", "name": null, "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), false, "bad_cmac".to_string()))
    );
    assert_eq!(
        last_counter(&f, UID_ACTIVE),
        0,
        "unverified tap must not advance high-water"
    );
    assert_eq!(audit_count(&f, UID_ACTIVE, "bad_cmac"), 1);
}

#[tokio::test]
async fn second_tap_with_same_counter_is_counter_replay() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_ACTIVE, 1);

    let (status, first) = send(&f.app, Some(SECRET), payload(UID_ACTIVE, 1, &cmac)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["grant"], true);
    assert_eq!(last_counter(&f, UID_ACTIVE), 1);
    assert!(f.sink.pop().is_some(), "first tap publishes a cmd");

    let (status, second) = send(&f.app, Some(SECRET), payload(UID_ACTIVE, 1, &cmac)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        second,
        json!({"grant": false, "reason": "counter_replay", "name": null, "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), false, "counter_replay".to_string()))
    );
    assert_eq!(
        last_counter(&f, UID_ACTIVE),
        1,
        "replay must not change state"
    );
    assert_eq!(audit_count(&f, UID_ACTIVE, "counter_replay"), 1);
}

#[tokio::test]
async fn expired_membership_responds_member_inactive() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_EXPIRED, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_EXPIRED, 1, &cmac)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": false, "reason": "member_inactive", "name": null, "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), false, "member_inactive".to_string()))
    );
    // Crypto-valid tap advances the counter even when membership denies.
    assert_eq!(last_counter(&f, UID_EXPIRED), 1);
}

#[tokio::test]
async fn ban_override_responds_override() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_BANNED, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_BANNED, 1, &cmac)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": false, "reason": "override", "name": null, "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), false, "override".to_string()))
    );
    assert_eq!(last_counter(&f, UID_BANNED), 1);
}

#[tokio::test]
async fn revoked_tag_maps_to_override() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_REVOKED, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_REVOKED, 1, &cmac)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": false, "reason": "override", "name": null, "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), false, "override".to_string()))
    );
}

#[tokio::test]
async fn missing_member_row_maps_to_member_inactive() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_NO_MEMBER, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_NO_MEMBER, 1, &cmac)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": false, "reason": "member_inactive", "name": null, "pulse_ms": 300})
    );
    assert_eq!(
        f.sink.pop(),
        Some((DOOR.to_string(), false, "member_inactive".to_string()))
    );
}

#[tokio::test]
async fn wrong_shared_secret_is_401_json() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_ACTIVE, 1);

    let (status, body) = send(
        &f.app,
        Some("not-the-secret"),
        payload(UID_ACTIVE, 1, &cmac),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.get("error").is_some(), "401 body must be JSON: {body}");
    assert!(f.sink.len() == 0, "no cmd published without auth");
    assert_eq!(last_counter(&f, UID_ACTIVE), 0);
}

#[tokio::test]
async fn missing_shared_secret_is_401_json() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_ACTIVE, 1);

    let (status, body) = send(&f.app, None, payload(UID_ACTIVE, 1, &cmac)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.get("error").is_some(), "401 body must be JSON: {body}");
    assert_eq!(last_counter(&f, UID_ACTIVE), 0);
}

#[tokio::test]
async fn string_typed_counter_is_422_json() {
    let f = setup();

    let (status, body) = send(
        &f.app,
        Some(SECRET),
        json!({ "reader": DOOR, "uid": UID_ACTIVE, "counter": "5", "cmac": "00".repeat(16) }),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.get("error").is_some(), "422 body must be JSON: {body}");
    assert_eq!(last_counter(&f, UID_ACTIVE), 0);
}

#[tokio::test]
async fn counter_beyond_three_bytes_is_422_json() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_ACTIVE, 1);

    let (status, body) = send(&f.app, Some(SECRET), payload(UID_ACTIVE, 0x1000000, &cmac)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.get("error").is_some(), "422 body must be JSON: {body}");
    assert_eq!(last_counter(&f, UID_ACTIVE), 0);
}

#[tokio::test]
async fn unknown_request_field_is_422_json() {
    let f = setup();
    let cmac = cmac_hex(&f, UID_ACTIVE, 1);

    let mut body = payload(UID_ACTIVE, 1, &cmac);
    body["extra"] = json!("field");

    let (status, response) = send(&f.app, Some(SECRET), body).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        response.get("error").is_some(),
        "422 body must be JSON: {response}"
    );
    assert_eq!(last_counter(&f, UID_ACTIVE), 0);
}

#[tokio::test]
async fn malformed_hex_is_422_json() {
    let f = setup();

    let (status, body) = send(
        &f.app,
        Some(SECRET),
        json!({ "reader": DOOR, "uid": "04zz", "counter": 1, "cmac": "00".repeat(16) }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.get("error").is_some(), "422 body must be JSON: {body}");

    let (status, body) = send(
        &f.app,
        Some(SECRET),
        json!({ "reader": DOOR, "uid": UID_ACTIVE, "counter": 1, "cmac": "abc" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.get("error").is_some(), "422 body must be JSON: {body}");

    assert_eq!(last_counter(&f, UID_ACTIVE), 0, "422 must not change state");
    assert_eq!(f.sink.len(), 0, "rejected requests publish no cmd");
}

#[tokio::test]
async fn noop_sink_serves_requests_without_capture() {
    let db = NamedTempFile::new().expect("temp db file");
    let mut store = Store::open(db.path()).expect("store opens");
    let now = chrono::Utc::now().to_rfc3339();
    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m1', 'Test Member', datetime('now', '+10 days'))",
            [],
        )
        .expect("insert m1");
    store
        .enroll_tag(UID_ACTIVE, "m1", 1, &now)
        .expect("enroll tag");
    let store = Arc::new(Mutex::new(store));

    let state = AppState {
        store,
        master: Key::from_hex(MASTER_HEX).expect("master key hex"),
        secret: SECRET.to_string(),
        sink: Arc::new(NoopSink),
    };
    let app = access_control_verifier::app(state);

    let master = Key::from_hex(MASTER_HEX).expect("master key hex");
    let uid = Uid::from_hex(UID_ACTIVE).expect("uid hex");
    let cmac = hex::encode(cmac_for(&master, &uid, &TapCounter::from_u32(1)).0);

    let (status, body) = send(&app, Some(SECRET), payload(UID_ACTIVE, 1, &cmac)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"grant": true, "reason": "ok", "name": "Test Member", "pulse_ms": 300})
    );
}
