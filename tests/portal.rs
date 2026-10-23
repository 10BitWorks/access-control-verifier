use access_control_verifier::api::{AppState, NoopSink};
use access_control_verifier::crypto::Key;
use access_control_verifier::portal::{
    verify_session_token, SessionClaims, OIDC_COOKIE_NAME, SESSION_COOKIE_NAME,
};
use access_control_verifier::store::Store;
use axum::{
    body::Body,
    http::{header, HeaderMap, Request, StatusCode},
};
use jsonwebtoken::{EncodingKey, Header};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MASTER_HEX: &str = "000102030405060708090a0b0c0d0e0f";
const TEST_SECRET: &str = "test-session-secret-key-123456789";

struct TestFixture {
    app: axum::Router,
    _db: NamedTempFile,
    store: Arc<Mutex<Store>>,
}

fn create_session_cookie(username: &str, roles: Vec<String>) -> String {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = SessionClaims {
        sub: username.to_string(),
        username: username.to_string(),
        roles,
        exp: now + 3600,
        iat: now,
    };
    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .unwrap();
    format!("{SESSION_COOKIE_NAME}={token}")
}

fn setup_test_app() -> TestFixture {
    unsafe {
        std::env::set_var("AUTHENTIK_ISSUER", "https://auth.example.com");
        std::env::set_var("AUTHENTIK_CLIENT_ID", "test-client-id");
        std::env::set_var("AUTHENTIK_CLIENT_SECRET", "test-client-secret");
        std::env::set_var("PUBLIC_URL", "https://keys.example.com");
        std::env::set_var("SESSION_SECRET", TEST_SECRET);
        std::env::set_var("SESSION_LIFETIME_HOURS", "12");
        std::env::set_var("ADMIN_ROLE", "Onboarders");
        std::env::set_var("ADMIN_BEARER_TOKEN", "test-admin-token");
    }

    let db = NamedTempFile::new().expect("temp db file");
    let store = Store::open(db.path()).expect("store opens");
    let store = Arc::new(Mutex::new(store));

    let state = AppState {
        store: store.clone(),
        master: Key::from_hex(MASTER_HEX).unwrap(),
        secret: "secret".to_string(),
        sink: Arc::new(NoopSink),
        jobs: Arc::new(access_control_verifier::writer::NoopJobPublisher),
    };

    let app = access_control_verifier::app(state, None);

    TestFixture {
        app,
        _db: db,
        store,
    }
}

async fn get_request(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value, HeaderMap) {
    let mut builder = Request::builder().uri(uri);
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let req = builder.body(Body::empty()).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, body, headers)
}

async fn post_request(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
    body_val: Value,
) -> (StatusCode, Value, HeaderMap) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let req = builder.body(Body::from(body_val.to_string())).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, body, headers)
}

#[test]
fn test_jwt_session_roundtrip_and_admin_role() {
    let principal = verify_session_token(
        &create_session_cookie("alice", vec!["Onboarders".to_string()])
            [SESSION_COOKIE_NAME.len() + 1..],
        TEST_SECRET,
        "Onboarders",
    )
    .expect("session verifies");

    assert_eq!(principal.username, "alice");
    assert!(principal.is_admin());

    let non_admin = verify_session_token(
        &create_session_cookie("bob", vec!["RegularMember".to_string()])
            [SESSION_COOKIE_NAME.len() + 1..],
        TEST_SECRET,
        "Onboarders",
    )
    .expect("session verifies");

    assert_eq!(non_admin.username, "bob");
    assert!(!non_admin.is_admin());

    // Bad signature
    let bad = verify_session_token("invalid.jwt.token", TEST_SECRET, "Onboarders");
    assert!(bad.is_none());
}

#[tokio::test]
async fn test_root_redirects_to_me() {
    let f = setup_test_app();
    let (status, _, headers) = get_request(&f.app, "/", None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/me");
}

#[tokio::test]
async fn test_me_html_renders() {
    let f = setup_test_app();
    let (status, body, _) = get_request(&f.app, "/me", None).await;
    assert_eq!(status, StatusCode::OK);
    let html = body["raw"].as_str().unwrap();
    assert!(html.contains("10BitWorks Key Portal"));
}

#[tokio::test]
async fn test_me_status_unauthorized_without_session() {
    let f = setup_test_app();
    let (status, body, _) = get_request(&f.app, "/me/api/status", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
}

#[tokio::test]
async fn test_me_status_authorized() {
    let f = setup_test_app();
    let cookie = create_session_cookie("alice", vec!["Regular".to_string()]);

    // Seed member
    {
        let mut store = f.store.lock().unwrap();
        store.conn_mut().execute(
            "INSERT INTO members (member_key, display_name, active_until) VALUES ('alice', 'Alice Liddell', datetime('now', '+10 days'))",
            [],
        ).unwrap();
        store.conn_mut().execute(
            "INSERT INTO tags (uid, member_key, key_version, last_counter, status, enrolled_at) VALUES ('04010203040506', 'alice', 1, 0, 'active', datetime('now'))",
            [],
        ).unwrap();
    }

    let (status, body, _) = get_request(&f.app, "/me/api/status", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["principal"]["username"], "alice");
    assert_eq!(body["membership"]["display_name"], "Alice Liddell");
    assert_eq!(body["is_active"], true);
    assert_eq!(body["active_tag"]["uid"], "04010203040506");
}

#[tokio::test]
async fn test_admin_gating_bearer_and_session() {
    let f = setup_test_app();

    // 1. Anon -> 401
    let (status, _, _) = get_request(&f.app, "/admin/api/tags", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2. Bearer token -> 200
    let builder = Request::builder()
        .uri("/admin/api/tags")
        .header(header::AUTHORIZATION, "Bearer test-admin-token");
    let req = builder.body(Body::empty()).unwrap();
    let res = f.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 3. Non-admin session -> 403 on API and HTML
    let non_admin_cookie = create_session_cookie("charlie", vec!["Member".to_string()]);
    let (status, body, _) = get_request(&f.app, "/admin/api/tags", Some(&non_admin_cookie)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "forbidden: admin role required");

    let (html_status, html_body, _) = get_request(&f.app, "/admin", Some(&non_admin_cookie)).await;
    assert_eq!(html_status, StatusCode::FORBIDDEN);
    assert!(html_body["raw"]
        .as_str()
        .unwrap()
        .contains("Admin Access Required"));

    // 4. Admin session -> 200
    let admin_cookie = create_session_cookie("alice_admin", vec!["Onboarders".to_string()]);
    let (status, _, _) = get_request(&f.app, "/admin/api/tags", Some(&admin_cookie)).await;
    assert_eq!(status, StatusCode::OK);

    let (html_status, _, _) = get_request(&f.app, "/admin", Some(&admin_cookie)).await;
    assert_eq!(html_status, StatusCode::OK);
}

#[tokio::test]
async fn test_me_provision_guards_and_wildcard_device() {
    let f = setup_test_app();
    let cookie = create_session_cookie("alice", vec!["Member".to_string()]);

    // 1. No session -> 401
    let (status, _, _) = post_request(&f.app, "/me/provision", None, json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2. No member row in database -> 422
    let (status, body, _) = post_request(&f.app, "/me/provision", Some(&cookie), json!({})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("No membership record"));

    // Seed expired member
    {
        let mut store = f.store.lock().unwrap();
        store.conn_mut().execute(
            "INSERT INTO members (member_key, display_name, active_until) VALUES ('alice', 'Alice', datetime('now', '-20 days'))",
            [],
        ).unwrap();
        store.conn_mut().execute(
            "INSERT INTO devices (device_id, role, presence) VALUES ('writer-01', 'writer', 'online')",
            [],
        ).unwrap();
    }

    // 3. Member inactive -> 403
    let (status, body, _) = post_request(&f.app, "/me/provision", Some(&cookie), json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("inactive or expired"));

    // Activate member
    {
        let mut store = f.store.lock().unwrap();
        store.conn_mut().execute(
            "UPDATE members SET active_until = datetime('now', '+30 days') WHERE member_key = 'alice'",
            [],
        ).unwrap();
    }

    // 4. Successful provision: creates job with TTL=60s and device_id="*"
    let (status, body, _) = post_request(&f.app, "/me/provision", Some(&cookie), json!({})).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["ttl_secs"], 60);
    let job_id = body["job_id"].as_str().unwrap();

    // Check store job record: device_id should be "*"
    {
        let mut store = f.store.lock().unwrap();
        let job_device: String = store
            .conn_mut()
            .query_row(
                "SELECT device_id FROM jobs WHERE job_id = ?1",
                rusqlite::params![job_id],
                |r| r.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(job_device, "*");
    }

    // 5. Duplicate pending job -> 409 Conflict
    let (status, body, _) = post_request(&f.app, "/me/provision", Some(&cookie), json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("already pending"));

    // 6. Claim job from writer-01 binds device_id to writer-01
    {
        let mut store = f.store.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let claim = store
            .claim_job_on_device(job_id, "04aabbccddeeff", &now, "writer-01")
            .unwrap();
        match claim {
            access_control_verifier::store::JobClaim::Claimed(j) => {
                assert_eq!(j.device_id, "writer-01");
                assert_eq!(j.uid, "04aabbccddeeff");
            }
            other => panic!("expected Claimed, got {:?}", other),
        }
    }
}

#[tokio::test]
async fn test_me_revoke_only_own_tags() {
    let f = setup_test_app();
    let alice_cookie = create_session_cookie("alice", vec!["Member".to_string()]);
    let _bob_cookie = create_session_cookie("bob", vec!["Member".to_string()]);

    {
        let mut store = f.store.lock().unwrap();
        store.conn_mut().execute(
            "INSERT INTO members (member_key, display_name, active_until) VALUES ('alice', 'Alice', datetime('now', '+30 days')), ('bob', 'Bob', datetime('now', '+30 days'))",
            [],
        ).unwrap();
        store.conn_mut().execute(
            "INSERT INTO tags (uid, member_key, status, enrolled_at) VALUES ('alice_tag', 'alice', 'active', datetime('now')), ('bob_tag', 'bob', 'active', datetime('now'))",
            [],
        ).unwrap();
    }

    // Alice revokes own tag
    let (status, body, _) =
        post_request(&f.app, "/me/revoke", Some(&alice_cookie), json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked_uids"], json!(["alice_tag"]));

    // Verify Bob's tag is still active and Alice's tag is revoked
    {
        let mut store = f.store.lock().unwrap();
        let alice_status: String = store
            .conn_mut()
            .query_row("SELECT status FROM tags WHERE uid = 'alice_tag'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap();
        let bob_status: String = store
            .conn_mut()
            .query_row("SELECT status FROM tags WHERE uid = 'bob_tag'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap();

        assert_eq!(alice_status, "revoked");
        assert_eq!(bob_status, "active");
    }
}

#[tokio::test]
async fn test_me_taps_filters_to_own_uids() {
    let f = setup_test_app();
    let alice_cookie = create_session_cookie("alice", vec!["Member".to_string()]);

    {
        let mut store = f.store.lock().unwrap();
        store.conn_mut().execute(
            "INSERT INTO members (member_key, display_name, active_until) VALUES ('alice', 'Alice', datetime('now', '+30 days')), ('bob', 'Bob', datetime('now', '+30 days'))",
            [],
        ).unwrap();
        store.conn_mut().execute(
            "INSERT INTO tags (uid, member_key, status, enrolled_at) VALUES ('alice_tag', 'alice', 'active', datetime('now')), ('bob_tag', 'bob', 'active', datetime('now'))",
            [],
        ).unwrap();
        // Record taps
        store
            .conn_mut()
            .execute(
                "INSERT INTO audit_log (ts, device_id, uid, decision, reason) VALUES 
             ('2026-10-20T10:00:00Z', 'front_door', 'alice_tag', 'granted', 'ok'),
             ('2026-10-20T11:00:00Z', 'front_door', 'bob_tag', 'granted', 'ok'),
             ('2026-10-20T12:00:00Z', 'front_door', 'alice_tag', 'denied', 'bad_cmac')",
                [],
            )
            .unwrap();
    }

    let (status, body, _) = get_request(&f.app, "/me/api/taps", Some(&alice_cookie)).await;
    assert_eq!(status, StatusCode::OK);
    let taps = body.as_array().unwrap();
    assert_eq!(taps.len(), 2);
    assert_eq!(taps[0]["uid"], "alice_tag");
    assert_eq!(taps[1]["uid"], "alice_tag");
}

#[tokio::test]
async fn test_oidc_callback_flow_with_mock_server() {
    let mock_server = MockServer::start().await;
    let issuer_url = mock_server.uri();

    unsafe {
        std::env::set_var("AUTHENTIK_ISSUER", &issuer_url);
        std::env::set_var("AUTHENTIK_CLIENT_ID", "mock-client-id");
        std::env::set_var("AUTHENTIK_CLIENT_SECRET", "mock-client-secret");
        std::env::set_var("PUBLIC_URL", "https://keys.example.com");
        std::env::set_var("SESSION_SECRET", TEST_SECRET);
        std::env::set_var("ADMIN_ROLE", "Onboarders");
    }

    // Discovery mock
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_endpoint": format!("{}/authorize", issuer_url),
            "token_endpoint": format!("{}/token", issuer_url),
            "jwks_uri": format!("{}/jwks", issuer_url),
        })))
        .mount(&mock_server)
        .await;

    // Create an unverified ID token with RS256 / HS256 claims
    let id_token_claims = json!({
        "iss": issuer_url,
        "aud": "mock-client-id",
        "exp": (chrono::Utc::now().timestamp() + 3600),
        "nonce": "test-nonce-123",
        "preferred_username": "mock_alice",
        "roles": ["Onboarders"]
    });
    let id_token = jsonwebtoken::encode(
        &Header::default(),
        &id_token_claims,
        &EncodingKey::from_secret(b"dummy-key"),
    )
    .unwrap();

    // Token endpoint mock
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "id_token": id_token,
        })))
        .mount(&mock_server)
        .await;

    let db = NamedTempFile::new().expect("temp db file");
    let store = Arc::new(Mutex::new(Store::open(db.path()).unwrap()));
    let state = AppState {
        store,
        master: Key::from_hex(MASTER_HEX).unwrap(),
        secret: "secret".to_string(),
        sink: Arc::new(NoopSink),
        jobs: Arc::new(access_control_verifier::writer::NoopJobPublisher),
    };
    let app = access_control_verifier::app(state, None);

    // Setup flow cookie
    let flow_json = json!({
        "pkce_verifier": "test_pkce_verifier_string_12345678901234567890",
        "csrf_token": "test-csrf-state",
        "nonce": "test-nonce-123",
    })
    .to_string();
    let flow_cookie = format!("{OIDC_COOKIE_NAME}={flow_json}");

    // Test callback CSRF mismatch -> 400
    let (status, _, _) = get_request(
        &app,
        "/auth/callback?code=mock_code&state=wrong-state",
        Some(&flow_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Test callback happy path -> 303 Redirect to /me with session cookie
    let (status, _, headers) = get_request(
        &app,
        "/auth/callback?code=mock_code&state=test-csrf-state",
        Some(&flow_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/me");

    let set_cookies = headers.get_all(header::SET_COOKIE);
    let has_session_cookie = set_cookies
        .iter()
        .any(|c| c.to_str().unwrap_or("").contains(SESSION_COOKIE_NAME));
    assert!(
        has_session_cookie,
        "session cookie should be set in headers"
    );
}
