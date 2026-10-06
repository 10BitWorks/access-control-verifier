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
    std::env::set_var("ADMIN_BEARER_TOKEN", "test-token");
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
