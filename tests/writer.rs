use access_control_verifier::crypto::{diversify, Key, Uid};
use access_control_verifier::mqtt::claim_and_build;
use access_control_verifier::store::Store;
use access_control_verifier::writer::{router, JobPublisher, WriterState, MAX_TTL_SECS};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
use tower::ServiceExt;

const MASTER_HEX: &str = "000102030405060708090a0b0c0d0e0f";
const ADMIN_TOKEN: &str = "test-admin-token";

const UID_NEW: &str = "04010203040506";
const DEVICE_WRITER: &str = "writer-01";
const DEVICE_GATE: &str = "door-gate";
const MEMBER: &str = "m1";

#[derive(Clone, Default)]
struct RecordingPublisher {
    records: Arc<Mutex<Vec<(String, String)>>>,
}

impl RecordingPublisher {
    fn len(&self) -> usize {
        self.records.lock().expect("records lock").len()
    }

    fn last(&self) -> Option<(String, String)> {
        self.records.lock().expect("records lock").last().cloned()
    }
}

impl JobPublisher for RecordingPublisher {
    fn publish_job(&self, device_id: &str, payload: &str) {
        self.records
            .lock()
            .expect("records lock")
            .push((device_id.to_string(), payload.to_string()));
    }
}

struct Fixture {
    app: axum::Router,
    store: Arc<Mutex<Store>>,
    pubq: RecordingPublisher,
    _db: NamedTempFile,
}

fn build() -> Fixture {
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
        .expect("insert member");
    store
        .conn_mut()
        .execute(
            "INSERT INTO devices (device_id, role, offline_verify, presence)
             VALUES ('writer-01', 'writer', 0, 'online')",
            [],
        )
        .expect("insert writer device");
    store
        .conn_mut()
        .execute(
            "INSERT INTO devices (device_id, role, offline_verify, presence)
             VALUES ('door-gate', 'gate', 0, 'online')",
            [],
        )
        .expect("insert gate device");

    let pubq = RecordingPublisher::default();
    let state = WriterState {
        store: Arc::new(Mutex::new(store)),
        master: Key::from_hex(MASTER_HEX).expect("master key hex"),
        admin_token: ADMIN_TOKEN.to_string(),
        jobs: Arc::new(pubq.clone()),
    };
    let store = state.store.clone();
    let _ = now;
    Fixture {
        app: router(state),
        store,
        pubq,
        _db: db,
    }
}

async fn post(
    app: &axum::Router,
    uri: &str,
    bearer: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        builder = builder.header("authorization", format!("Bearer {t}"));
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

fn create_body(uid: &str) -> Value {
    json!({ "uid": uid, "member_key": MEMBER, "device_id": DEVICE_WRITER })
}

async fn create_ok(f: &Fixture) -> Value {
    let (status, body) = post(&f.app, "/v1/jobs", Some(ADMIN_TOKEN), create_body(UID_NEW)).await;
    assert_eq!(status, StatusCode::CREATED, "create body: {body}");
    body
}

fn counter_of(f: &Fixture, uid: &str) -> i64 {
    f.store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT last_counter FROM tags WHERE uid = ?1",
            rusqlite::params![uid],
            |row| row.get(0),
        )
        .expect("tag row exists")
}

fn audit_count(f: &Fixture, reason: &str) -> i64 {
    f.store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE reason = ?1",
            rusqlite::params![reason],
            |row| row.get(0),
        )
        .expect("audit query runs")
}

#[tokio::test]
async fn job_lifecycle_create_deliver_consume() {
    let f = build();

    // Create.
    let created = create_ok(&f).await;
    let job_id = created["job_id"].as_str().expect("job_id").to_string();
    assert!(!created["expires_at"].as_str().unwrap().is_empty());

    // Deliver: exactly one publish, to the writer device, correct topic target.
    assert_eq!(f.pubq.len(), 1);
    let (device_id, payload) = f.pubq.last().expect("one delivery");
    assert_eq!(device_id, DEVICE_WRITER);

    let delivered: Value = serde_json::from_str(&payload).expect("payload is JSON");
    assert_eq!(delivered["uid"], UID_NEW);
    assert_eq!(delivered["job_id"], job_id);
    assert!(!delivered["expires_at"].as_str().unwrap().is_empty());
    assert_eq!(delivered["sun_config"]["key_version"], 1);
    assert_eq!(delivered["sun_config"]["cmac_bytes"], 8);

    // Per-tag key only; master key never in any payload.
    let uid = Uid::from_hex(UID_NEW).expect("uid");
    let expected_key = hex::encode(diversify(&Key::from_hex(MASTER_HEX).unwrap(), &uid).0);
    assert_eq!(delivered["key"], expected_key);
    assert!(
        !payload.contains(MASTER_HEX),
        "master key leaked in payload"
    );

    // Consume: tag bound to member, last_counter from card.
    let (status, body) = post(
        &f.app,
        &format!("/v1/job/{job_id}"),
        None,
        json!({ "counter": 42 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "done body: {body}");
    assert_eq!(body["enrolled"], true);
    assert_eq!(body["uid"], UID_NEW);
    assert_eq!(counter_of(&f, UID_NEW), 42);
    assert_eq!(audit_count(&f, "job_done"), 1);

    // Second consume attempt -> 410 Gone, counter unchanged.
    let (status, _) = post(
        &f.app,
        &format!("/v1/job/{job_id}"),
        None,
        json!({ "counter": 99 }),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(counter_of(&f, UID_NEW), 42, "replay must not rebind");
    assert_eq!(audit_count(&f, "job_reused"), 1);
    assert_eq!(f.pubq.len(), 1, "no key redelivery on consume");
}

#[tokio::test]
async fn expired_job_gone_with_audit_and_no_redelivery() {
    let f = build();
    let created = create_ok(&f).await;
    let job_id = created["job_id"].as_str().expect("job_id").to_string();

    // Age the job past its TTL.
    f.store
        .lock()
        .expect("store lock")
        .conn_mut()
        .execute(
            "UPDATE jobs SET expires_at = '2000-01-01T00:00:00+00:00' WHERE job_id = ?1",
            rusqlite::params![job_id],
        )
        .expect("age job");

    let (status, _) = post(
        &f.app,
        &format!("/v1/job/{job_id}"),
        None,
        json!({ "counter": 7 }),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(audit_count(&f, "job_expired"), 1);
    assert_eq!(f.pubq.len(), 1, "expiry must not trigger key redelivery");

    let rows: i64 = f
        .store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT COUNT(*) FROM tags WHERE uid = ?1",
            rusqlite::params![UID_NEW],
            |row| row.get(0),
        )
        .expect("count tags");
    assert_eq!(rows, 0, "expired job must not enroll");
}

#[tokio::test]
async fn non_writer_device_denied_delivery() {
    let f = build();
    let body = json!({ "uid": UID_NEW, "member_key": MEMBER, "device_id": DEVICE_GATE });
    let (status, resp) = post(&f.app, "/v1/jobs", Some(ADMIN_TOKEN), body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "resp: {resp}");
    assert_eq!(f.pubq.len(), 0, "no delivery to non-writer");

    let jobs: i64 = f
        .store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
        .expect("count jobs");
    assert_eq!(jobs, 0, "denied create must not persist a job");
}

#[tokio::test]
async fn unknown_device_denied() {
    let f = build();
    let body = json!({ "uid": UID_NEW, "member_key": MEMBER, "device_id": "ghost-device" });
    let (status, _) = post(&f.app, "/v1/jobs", Some(ADMIN_TOKEN), body).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(f.pubq.len(), 0);
}

#[tokio::test]
async fn missing_or_wrong_bearer_rejected() {
    let f = build();
    let (status, _) = post(&f.app, "/v1/jobs", None, create_body(UID_NEW)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = post(&f.app, "/v1/jobs", Some("wrong"), create_body(UID_NEW)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(f.pubq.len(), 0);
    assert_eq!(
        f.store
            .lock()
            .expect("store lock")
            .conn_mut()
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
            .expect("count jobs"),
        0
    );
}

#[tokio::test]
async fn ttl_over_max_rejected() {
    let f = build();
    let body = json!({
        "uid": UID_NEW,
        "member_key": MEMBER,
        "device_id": DEVICE_WRITER,
        "ttl_secs": MAX_TTL_SECS + 1,
    });
    let (status, _) = post(&f.app, "/v1/jobs", Some(ADMIN_TOKEN), body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(f.pubq.len(), 0);
}

#[tokio::test]
async fn invalid_uid_rejected() {
    let f = build();
    let (status, _) = post(&f.app, "/v1/jobs", Some(ADMIN_TOKEN), create_body("nope")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(f.pubq.len(), 0);
}

#[tokio::test]
async fn unknown_job_done_is_404() {
    let f = build();
    let (status, _) = post(
        &f.app,
        "/v1/job/00000000000000000000000000000000",
        None,
        json!({ "counter": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn counter_out_of_range_rejected() {
    let f = build();
    let created = create_ok(&f).await;
    let job_id = created["job_id"].as_str().expect("job_id");
    let (status, _) = post(
        &f.app,
        &format!("/v1/job/{job_id}"),
        None,
        json!({ "counter": 0x1000000u64 }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn wildcard_create_arms_without_key() {
    let f = build();
    let body = json!({ "member_key": MEMBER, "device_id": DEVICE_WRITER });
    let (status, created) = post(&f.app, "/v1/jobs", Some(ADMIN_TOKEN), body).await;
    assert_eq!(status, StatusCode::CREATED, "body: {created}");
    let job_id = created["job_id"].as_str().expect("job_id").to_string();

    // Exactly one delivery, to the writer, carrying the arming payload only.
    assert_eq!(f.pubq.len(), 1);
    let (device_id, payload) = f.pubq.last().expect("one delivery");
    assert_eq!(device_id, DEVICE_WRITER);

    let delivered: Value = serde_json::from_str(&payload).expect("payload is JSON");
    assert_eq!(delivered["uid"], "");
    assert_eq!(delivered["key"], "");
    assert_eq!(delivered["job_id"], job_id);
    assert_eq!(delivered["sun_config"]["key_version"], 1);
    assert_eq!(delivered["sun_config"]["cmac_bytes"], 8);
    assert!(
        !payload.contains(MASTER_HEX),
        "master key leaked in payload"
    );
}

#[test]
fn wildcard_claim_binds_uid_and_builds_keyed_payload() {
    let f = build();
    let now = chrono::Utc::now().to_rfc3339();
    let expires = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
    let job_id = {
        let mut store = f.store.lock().expect("store lock");
        store
            .create_job("", MEMBER, DEVICE_WRITER, &now, &expires)
            .expect("create wildcard job")
    };

    let master = Key::from_hex(MASTER_HEX).expect("master key hex");

    // First claim binds the uid and yields the keyed payload on the job topic.
    let (topic, payload) =
        claim_and_build(&f.store, &master, DEVICE_WRITER, &job_id, UID_NEW, &now)
            .expect("claim granted");
    assert_eq!(topic, format!("writer/{DEVICE_WRITER}/job"));

    let delivered: Value = serde_json::from_str(&payload).expect("payload is JSON");
    assert_eq!(delivered["uid"], UID_NEW.to_ascii_lowercase());
    assert_eq!(delivered["job_id"], job_id);
    let uid = Uid::from_hex(UID_NEW).expect("uid");
    let expected_key = hex::encode(diversify(&master, &uid).0);
    assert_eq!(delivered["key"], expected_key);
    assert!(
        !payload.contains(MASTER_HEX),
        "master key leaked in payload"
    );

    // A second claim from a different tag is refused.
    assert!(
        claim_and_build(
            &f.store,
            &master,
            DEVICE_WRITER,
            &job_id,
            "0405060708090a",
            &now
        )
        .is_none(),
        "second tag must not claim a bound job"
    );

    // A malformed uid is refused without mutating the job.
    assert!(claim_and_build(&f.store, &master, DEVICE_WRITER, &job_id, "zz", &now).is_none());
}

#[tokio::test]
async fn test_claim_nack_on_expired_and_consumed_jobs() {
    use access_control_verifier::mqtt::{resolve_claim, ClaimResult};

    let f = build();
    let master = Key::from_hex(MASTER_HEX).expect("master key hex");
    let now = "2026-10-06T10:00:00Z";

    // 1. Create a job that expires in 10 seconds
    let expires = "2026-10-06T10:00:10Z";
    let job_id = {
        let mut store = f.store.lock().unwrap();
        store
            .create_job("", "member_1", DEVICE_WRITER, now, expires)
            .unwrap()
    };

    // Before expiry, claim resolves to KeyedJob
    let res_valid = resolve_claim(&f.store, &master, DEVICE_WRITER, &job_id, UID_NEW, now);
    match res_valid {
        ClaimResult::KeyedJob { topic, payload } => {
            assert_eq!(topic, format!("writer/{DEVICE_WRITER}/job"));
            assert!(payload.contains(&job_id));
        }
        other => panic!("expected KeyedJob, got {other:?}"),
    }

    // Now test claim when expired (now is past expires_at)
    let past_now = "2026-10-06T10:00:15Z";
    let res_expired = resolve_claim(&f.store, &master, DEVICE_WRITER, &job_id, UID_NEW, past_now);
    match res_expired {
        ClaimResult::Nack { topic, payload } => {
            assert_eq!(topic, format!("writer/{DEVICE_WRITER}/job"));
            let v: Value = serde_json::from_str(&payload).expect("json");
            assert_eq!(v["nack"], true);
            assert_eq!(v["job_id"], job_id);
            assert_eq!(v["reason"], "expired");
        }
        other => panic!("expected Nack(expired), got {other:?}"),
    }

    // Now complete (consume) the job
    {
        let mut store = f.store.lock().unwrap();
        // Consume it
        let _ = access_control_verifier::writer::consume_job(
            &mut store,
            &job_id,
            10,
            now,
            Some(DEVICE_WRITER),
        );
    }

    // Test claim against consumed job
    let res_consumed = resolve_claim(&f.store, &master, DEVICE_WRITER, &job_id, UID_NEW, now);
    match res_consumed {
        ClaimResult::Nack { topic, payload } => {
            assert_eq!(topic, format!("writer/{DEVICE_WRITER}/job"));
            let v: Value = serde_json::from_str(&payload).expect("json");
            assert_eq!(v["nack"], true);
            assert_eq!(v["job_id"], job_id);
            assert_eq!(v["reason"], "consumed");
        }
        other => panic!("expected Nack(consumed), got {other:?}"),
    }
}

#[tokio::test]
async fn test_arm_populates_member_key_in_audit_log() {
    let f = build();

    let (status, body) = post(
        &f.app,
        "/v1/jobs",
        Some(ADMIN_TOKEN),
        json!({
            "uid": "",
            "member_key": "audit_member_42",
            "device_id": DEVICE_WRITER,
            "ttl_secs": 60,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let _job_id = body["job_id"].as_str().unwrap();

    let store = f.store.lock().unwrap();
    let audits = store.list_audit(10, None, None).unwrap();
    let arm_audit = audits
        .iter()
        .find(|a| a.reason == "provision_armed")
        .expect("provision_armed audit log found");

    assert_eq!(arm_audit.member_key.as_deref(), Some("audit_member_42"));
    assert_eq!(arm_audit.device_id.as_deref(), Some(DEVICE_WRITER));
}
