use access_control_verifier::api::{AppState, NoopSink};
use access_control_verifier::crypto::Key;
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

struct Fixture {
    app: axum::Router,
    _db: NamedTempFile,
}

fn setup() -> Fixture {
    unsafe {
        std::env::set_var("ADMIN_BEARER_TOKEN", "test-token");
    }
    let db = NamedTempFile::new().expect("temp db file");
    let mut store = Store::open(db.path()).expect("store opens");

    // Add member "m2" so overrides test doesn't fail foreign key
    store.conn_mut().execute(
        "INSERT INTO members (member_key, display_name, active_until) VALUES ('m2', 'Member 2', datetime('now', '+10 days'))",
        [],
    ).unwrap();

    let store = Arc::new(Mutex::new(store));
    let state = AppState {
        store,
        master: Key::from_hex(MASTER_HEX).unwrap(),
        secret: "secret".to_string(),
        sink: Arc::new(NoopSink),
        jobs: Arc::new(access_control_verifier::writer::NoopJobPublisher),
    };

    Fixture {
        app: access_control_verifier::admin::router(state),
        _db: db,
    }
}

async fn get(app: &axum::Router, path: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().uri(path);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {}", t));
    }
    let req = builder.body(Body::empty()).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    (status, body)
}

async fn post(
    app: &axum::Router,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {}", t));
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        let s = String::from_utf8_lossy(&bytes);
        println!("Non-JSON resp: {}", s);
        json!({"error": s})
    });
    (status, resp)
}

#[tokio::test]
async fn missing_token_returns_401() {
    let f = setup();
    let (status, _) = get(&f.app, "/admin/api/tags", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let f = setup();
    let (status, _) = get(&f.app, "/admin/api/tags", Some("wrong-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_token_allows_access() {
    let f = setup();
    let (status, body) = get(&f.app, "/admin/api/tags", Some("test-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn admin_flow_enroll_revoke_tag() {
    let f = setup();

    // Enroll
    let (status, body) = post(
        &f.app,
        "/admin/api/tags/enroll",
        Some("test-token"),
        json!({
            "uid": "04000000000000",
            "member_key": "m2",
            "key_version": 1
        }),
    )
    .await;
    if status != StatusCode::OK {
        println!("BODY: {:?}", body);
    }
    assert_eq!(status, StatusCode::OK);

    // List
    let (status, body) = get(&f.app, "/admin/api/tags", Some("test-token")).await;
    assert_eq!(status, StatusCode::OK);
    let tags = body.as_array().unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0]["uid"], "04000000000000");
    assert_eq!(tags[0]["status"], "active");

    // Revoke
    let (status, body) = post(
        &f.app,
        "/admin/api/tags/04000000000000/revoke",
        Some("test-token"),
        json!({}),
    )
    .await;
    if status != StatusCode::OK {
        println!("BODY: {:?}", body);
    }
    assert_eq!(status, StatusCode::OK);

    // List again
    let (_, body) = get(&f.app, "/admin/api/tags", Some("test-token")).await;
    let tags = body.as_array().unwrap();
    assert_eq!(tags[0]["status"], "revoked");
}

#[tokio::test]
async fn admin_flow_overrides_and_devices() {
    let f = setup();

    // Create override
    let (status, body) = post(
        &f.app,
        "/admin/api/overrides",
        Some("test-token"),
        json!({
            "member_key": "m2",
            "uid": null,
            "kind": "ban",
            "expires_at": null,
            "note": "testing admin override"
        }),
    )
    .await;
    if status != StatusCode::OK {
        println!("BODY: {:?}", body);
    }
    assert_eq!(status, StatusCode::OK);
    assert!(body["id"].is_number());

    // List overrides
    let (_, body) = get(&f.app, "/admin/api/overrides", Some("test-token")).await;
    let overrides = body.as_array().unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0]["kind"], "ban");

    // Upsert device
    let (status, body) = post(
        &f.app,
        "/admin/api/devices",
        Some("test-token"),
        json!({
            "device_id": "front_door",
            "role": "gate",
            "offline_verify": true
        }),
    )
    .await;
    if status != StatusCode::OK {
        println!("BODY: {:?}", body);
    }
    assert_eq!(status, StatusCode::OK);

    // List devices
    let (_, body) = get(&f.app, "/admin/api/devices", Some("test-token")).await;
    let devices = body.as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["device_id"], "front_door");
    assert_eq!(devices[0]["offline_verify"], true);
}

#[tokio::test]
async fn admin_set_device_role() {
    let f = setup();

    // Provision a reader.
    let (status, _) = post(
        &f.app,
        "/admin/api/devices",
        Some("test-token"),
        json!({ "device_id": "reader-01", "role": "gate", "offline_verify": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Promote it to a writer/reader.
    let (status, body) = post(
        &f.app,
        "/admin/api/devices/reader-01/role",
        Some("test-token"),
        json!({ "role": "both" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (_, body) = get(&f.app, "/admin/api/devices", Some("test-token")).await;
    let reader = body
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["device_id"] == "reader-01")
        .expect("reader present");
    assert_eq!(reader["role"], "both");

    // Invalid role is rejected.
    let (status, _) = post(
        &f.app,
        "/admin/api/devices/reader-01/role",
        Some("test-token"),
        json!({ "role": "admin" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Unknown device is rejected.
    let (status, _) = post(
        &f.app,
        "/admin/api/devices/ghost/role",
        Some("test-token"),
        json!({ "role": "writer" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Unauthenticated is rejected.
    let (status, _) = post(
        &f.app,
        "/admin/api/devices/reader-01/role",
        None,
        json!({ "role": "writer" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// T6: provisioning panel — pending list, cancel, arm
// ---------------------------------------------------------------------------

/// DELETE helper.
async fn del(app: &axum::Router, path: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("DELETE").uri(path);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {}", t));
    }
    let req = builder.body(Body::empty()).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    (status, body)
}

fn writer_fixture() -> Fixture {
    unsafe {
        std::env::set_var("ADMIN_BEARER_TOKEN", "test-token");
    }
    let db = NamedTempFile::new().expect("temp db file");
    let mut store = Store::open(db.path()).expect("store opens");
    store.conn_mut().execute(
        "INSERT INTO members (member_key, display_name, active_until) VALUES ('m1', 'Member 1', datetime('now', '+10 days'))",
        [],
    ).unwrap();
    store.conn_mut().execute(
        "INSERT INTO devices (device_id, role, presence, last_seen) VALUES ('writer-1', 'writer', 'offline', '')",
        [],
    ).unwrap();
    let store = Arc::new(Mutex::new(store));
    let state = AppState {
        store,
        master: Key::from_hex(MASTER_HEX).unwrap(),
        secret: "secret".to_string(),
        sink: Arc::new(NoopSink),
        jobs: Arc::new(access_control_verifier::writer::NoopJobPublisher),
    };
    Fixture {
        app: access_control_verifier::admin::router(state),
        _db: db,
    }
}

#[tokio::test]
async fn test_pending_list_unknown_device_returns_empty_array() {
    let f = writer_fixture();
    let (status, body) = get(
        &f.app,
        "/admin/api/jobs/pending?device=who-dis",
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));
}

#[tokio::test]
async fn test_arm_and_cancel_wildcard_job() {
    let f = writer_fixture();

    // Arm a wildcard job through the admin route.
    let (status, body) = post(
        &f.app,
        "/admin/api/jobs",
        Some("test-token"),
        json!({ "member_key": "m1", "device_id": "writer-1" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "arm body: {}", body);
    let job_id = body["job_id"].as_str().expect("job_id").to_string();

    // Pending list shows it, uid still empty (wildcard).
    let (status, body) = get(&f.app, "/admin/api/jobs/pending", Some("test-token")).await;
    assert_eq!(status, StatusCode::OK);
    let jobs = body.as_array().expect("array");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["job_id"], json!(job_id));
    assert_eq!(jobs[0]["uid"], json!(""));

    // Cancel marks the job consumed (fail_job audit job_failed).
    let (status, body) = del(
        &f.app,
        &format!("/admin/api/jobs/{}", job_id),
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cancel body: {}", body);
    assert_eq!(body["status"], json!("cancelled"));

    // Pending list is now empty for that job.
    let (_, body) = get(&f.app, "/admin/api/jobs/pending", Some("test-token")).await;
    assert_eq!(body, json!([]));

    // Second cancel: job already consumed -> 404.
    let (status, _) = del(
        &f.app,
        &format!("/admin/api/jobs/{}", job_id),
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_arm_rejects_non_writer_device_and_bad_uid() {
    let f = writer_fixture();

    // Gate device is not a writer.
    let (status, _) = post(
        &f.app,
        "/admin/api/jobs",
        Some("test-token"),
        json!({ "member_key": "m1", "device_id": "gate-1" }),
    )
    .await;
    // gate-1 doesn't exist at all -> 404 (unknown device).
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Bad uid hex -> 422.
    let (status, _) = post(
        &f.app,
        "/admin/api/jobs",
        Some("test-token"),
        json!({ "uid": "nothex", "member_key": "m1", "device_id": "writer-1" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_admin_page_renders_provisioning_section() {
    let f = writer_fixture();
    let mut builder = Request::builder().uri("/admin");
    builder = builder.header("Authorization", "Bearer test-token");
    let req = builder.body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(
        html.contains("id=\"provision\""),
        "provision section missing"
    );
    assert!(html.contains("Arm writer"), "arm button missing");
    assert!(html.contains("/admin/api/jobs"), "arm endpoint missing");
}

#[tokio::test]
async fn test_admin_page_renders_v2_surfaces() {
    let f = setup();
    let mut builder = Request::builder().uri("/admin");
    builder = builder.header("Authorization", "Bearer test-token");
    let req = builder.body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);

    // Audit table has member key column
    assert!(
        html.contains("<th>Member Key</th>"),
        "audit log table missing Member Key header"
    );

    // Anomaly Feed section and table
    assert!(
        html.contains("id=\"anomalies-table\""),
        "anomalies table missing"
    );
    assert!(
        html.contains("Anomaly Feed"),
        "anomaly feed heading missing"
    );

    // Tap Reports section and table
    assert!(
        html.contains("id=\"tap-reports-table\""),
        "tap-reports table missing"
    );
    assert!(html.contains("Tap Reports"), "tap reports heading missing");

    // Devices & v2 sync notice
    assert!(
        html.contains("Devices &amp; v2 Sync") || html.contains("Devices & v2 Sync"),
        "devices & v2 sync heading missing"
    );
    assert!(
        html.contains("roster_gen / hello handshakes"),
        "v2 sync streaming note missing"
    );
}

#[tokio::test]
async fn test_anomalies_and_tap_reports_api_auth_and_filters() {
    let f = setup();

    // 1. Unauthenticated requests return 401
    let (status, _) = get(&f.app, "/admin/api/anomalies", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get(&f.app, "/admin/api/tap-reports", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Populate test data directly
    {
        // We can access store via state or insert in db
        // Wait, setup() provides store Arc in state, but f only has app.
        // Let's create an app with store accessible or use raw sql on f._db.path()
        let conn = rusqlite::Connection::open(f._db.path()).unwrap();
        conn.execute(
            "INSERT INTO anomalies (id, ts, device_id, uid, kind, detail) VALUES
             (1, '2026-10-28T10:00:00Z', 'keygate-frontdoor', '04aabbccddee01', 'counter_regression', 'regressed counter'),
             (2, '2026-10-28T10:05:00Z', 'keygate-backdoor', '04aabbccddee02', 'saturation', 'counter maxed');",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO tap_reports (tap_id, device_id, uid, counter, decision, reason, time_uncertain, dev_ts, recv_ts, key_version, kind) VALUES
             ('keygate-frontdoor:1', 'keygate-frontdoor', '04aabbccddee01', 101, 'granted', 'granted', 0, '2026-10-28T10:00:00Z', '2026-10-28T10:00:01Z', 1, 'dna'),
             ('keygate-frontdoor:2', 'keygate-frontdoor', '04aabbccddee01', 102, 'granted', 'granted', 1, '2026-10-28T10:01:00Z', '2026-10-28T10:01:01Z', 1, 'dna'),
             ('keygate-backdoor:1', 'keygate-backdoor', '04aabbccddee02', 50, 'denied', 'expired', 0, '2026-10-28T10:02:00Z', '2026-10-28T10:02:01Z', 1, 'dna');",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO audit_log (id, ts, device_id, uid, counter, decision, reason, member_key) VALUES
             (10, '2026-10-28T10:00:00Z', 'keygate-frontdoor', '04aabbccddee01', 101, 'granted', 'granted', 'member-alice');",
            [],
        ).unwrap();
    }

    // 2. Fetch anomalies without filters
    let (status, body) = get(&f.app, "/admin/api/anomalies", Some("test-token")).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    // newest first (id 2 then 1)
    assert_eq!(arr[0]["id"], 2);
    assert_eq!(arr[1]["id"], 1);

    // Filter anomalies by kind
    let (status, body) = get(
        &f.app,
        "/admin/api/anomalies?kind=counter_regression",
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["kind"], "counter_regression");

    // Filter anomalies by device
    let (status, body) = get(
        &f.app,
        "/admin/api/anomalies?device=keygate-backdoor",
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["device_id"], "keygate-backdoor");

    // 3. Fetch tap-reports without filters
    let (status, body) = get(&f.app, "/admin/api/tap-reports", Some("test-token")).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 3);

    // Filter tap-reports by device
    let (status, body) = get(
        &f.app,
        "/admin/api/tap-reports?device=keygate-frontdoor",
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().all(|r| r["device_id"] == "keygate-frontdoor"));

    // Filter tap-reports by uid
    let (status, body) = get(
        &f.app,
        "/admin/api/tap-reports?uid=04aabbccddee02",
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["tap_id"], "keygate-backdoor:1");

    // Limit check
    let (status, body) = get(&f.app, "/admin/api/tap-reports?limit=1", Some("test-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);

    // Time uncertain check
    let (status, body) = get(
        &f.app,
        "/admin/api/tap-reports?device=keygate-frontdoor",
        Some("test-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    let has_tu = arr.iter().any(|r| r["time_uncertain"] == true);
    let has_not_tu = arr.iter().any(|r| r["time_uncertain"] == false);
    assert!(has_tu && has_not_tu);

    // 4. Audit log returns member_key
    let (status, body) = get(&f.app, "/admin/api/audit", Some("test-token")).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["member_key"], "member-alice");
}
