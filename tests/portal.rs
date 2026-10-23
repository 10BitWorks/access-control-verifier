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
use jsonwebtoken::{Algorithm, EncodingKey, Header};
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
    /// Held (never read) for the fixture's lifetime — see ENV_LOCK.
    #[allow(dead_code)]
    env_guard: std::sync::MutexGuard<'static, ()>,
}

/// See `TestFixture::env_guard`.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    let env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        env_guard,
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

// ---------------------------------------------------------------------------
// OIDC callback: ID-token signature verification via JWKS
// ---------------------------------------------------------------------------

// Test-only RSA key material (generated offline and embedded so tests need no
// runtime keygen and no extra dev-dependencies). Key A signs the mock ID
// tokens; RSA_KEY_B_N is an unrelated public modulus served by the JWKS mock
// in the wrong-key scenario.
const RSA_KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhJvJ47y9YtQFM
+3tfwVdqiWdCC4K1aysLWk5RzZtgDARy19BtCYQj9oHo7xdWYV6T0P73YdzvdA5w
cUxUNTCvsMPxRyFa9V7GRBFaB4uBhSBlzfbHJ5Gq/UZE3yonUVyUhwNhWXkocY9X
4g3zysQyrm75Ek3BztXw/3pzThzIgolMQGQ0hgB4AIlv7K65XmEBlLOcVUCypfHq
9DLWuIbpMoRiRt3FUwn1VZ+SB2/S/idrfpCHqyZxFLBmPzp1tjXheZmyDuui5EnY
vtSEN0A0c3kH06OP+HG0ylBPALg8+IOjnHEaaykdCWAX4mWMPDrOnIji0aa4jhpn
0Q9w2KzvAgMBAAECggEAA5I6E1f74MTSNfXhMZYf/FUcmawUESuXfbEbf+mqdr4K
DgZFTI1zlpxw2BB+xsR5mw+cE7FuLzAgkIEDjGxhjs/Xc8rEiSxOKgfnXI21FUNW
zbaUHPmQMm2dATem9AOy27o+f/tK1Czk8Khpvz2umf0xTmsPZ60PsKhkuVJ6W2XL
B7d0IIbAExfIUJp0pCClmaQCpwqmT4940yBTO2UYTBku4He0c/CXFTAE+dBXD6Hr
TKjNaov3b3E30o09KFEwCyX/k0dEXVmEynfkNxChY0Zv6OFWDWtVha9rlcgYf8Hy
NVWA3kJIZ9zPmn11MsDpT8eKpt2rtjNNlGQKBoIWdQKBgQD46omRQOccawwkSC/w
ho6SR/mK5riJMf0abPnh0ZlmX0JDo79MIe8vqX7zworogaIdYeECS5FK7l7gC2gt
3amMqnZkLsv0Dazo+TwuZJQwmQwakIUSAakPTAsFkrqbindhuF+h6ShlJicLd+xr
oVVzZ2O3FD2QGoIpHtSpurwLPQKBgQDnj0dNG4wGsMLLQ2BUpn0giivlGEr9o2/7
LWjteMn+IuDd87RJceD0FiBEK8K/OnYJphisUS+oL26y+2T5P235DCad/LZu/wTb
pJs7IQeNOqlylQuZX6thqmSY4I30WEJXagP+aX8vTaRHQIPn4z1zYJvWgkcb8acG
arIqt69LmwKBgDeEUAR2nlVHRuD8vLx/tmLH7M9fID9xR8tSDPWhwv4DNwtRBUSc
uPU/b5I8jLDI4Ph+sSnK4u/8dGqyAJ1iOAOorVkw2spnFm6r0BFk22xvZjSykQtw
FV3VDwxCKp6wZmoELkg1cY4F0WWMbM2goSdpIuNdf1GZp/g16SamAHTdAoGAQHfN
fBQ9SeeQdBLQEQFBOPv++Ito5XDJTn74BZVpd02ymViuSvxfitVWKmSclazrDAio
OeFoiUSbZ01CcXpNXdcaMUYYbJKngZc0eKPbfGBmqLYCQrM1/bz4wO9T1kF0Ru4H
Kp+ofzz4jbXSg47qnuK4wGII9iizPcAa1nXJYh0CgYEAlZ0Yvg1DYAvpiv7Mt4g1
i4UGj0QRvyecafNA230dIEAB0YTiPPsUv4lUsMsx27fFJ4ffejfWYqDgtSqsH84R
4lz+lgkhv9EXf5blalDeO2fw8kMT8+8VhmrhUWZrO8pxugLCrsDuRlMBJZh41GOA
L2LiJiU5CVUqSodH2eolcYI=
-----END PRIVATE KEY-----";
const RSA_KEY_A_N: &str = "4SbyeO8vWLUBTPt7X8FXaolnQguCtWsrC1pOUc2bYAwEctfQbQmEI_aB6O8XVmFek9D-92Hc73QOcHFMVDUwr7DD8UchWvVexkQRWgeLgYUgZc32xyeRqv1GRN8qJ1FclIcDYVl5KHGPV-IN88rEMq5u-RJNwc7V8P96c04cyIKJTEBkNIYAeACJb-yuuV5hAZSznFVAsqXx6vQy1riG6TKEYkbdxVMJ9VWfkgdv0v4na36Qh6smcRSwZj86dbY14XmZsg7rouRJ2L7UhDdANHN5B9Ojj_hxtMpQTwC4PPiDo5xxGmspHQlgF-JljDw6zpyI4tGmuI4aZ9EPcNis7w";
const RSA_KEY_B_N: &str = "01RBFoEQdW9_ahFugOVK2rgMr03Lw6XmdFpSzEqjl_k0cVi25Eyxj9-hbuL7v1dC7UWleUSc5I9uv6qNU16xW7X6QhbkaU9SlSjcdjRmMrGPgWmWn2FYY4vnrjHyy95Cr1aQVV_pSW4jH9oFY7dUPRxbeDdCWQj0wzgWBO2gKO7PDYEfUSNILWqMVfCDSj1vHubVimmF_OGRaM9LlHBY7vPUdObqNlfQE_sILBerqGhC48pAVNUO2Gyo4GlKQCWe_zQlf84wDlw8CTTQtPii56mOmSGCs1LG4kys7g3smZXn__G05USvnWnxtpMxgfvKg5GNC2n9Jdwag4vx1A-GFQ";

fn sign_rs256_id_token(pem: &str, kid: &str, claims: &Value) -> String {
    jsonwebtoken::encode(
        &Header {
            alg: Algorithm::RS256,
            kid: Some(kid.to_string()),
            ..Default::default()
        },
        claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

struct OidcCallbackMock {
    app: axum::Router,
    _db: NamedTempFile,
    _server: MockServer,
    flow_cookie: String,
}

/// Mock OIDC issuer whose token endpoint returns an RS256 ID token signed by
/// key A (with `token_kid`), and whose JWKS endpoint serves a single key with
/// kid `jwks_kid` and modulus `jwks_n`.
async fn setup_oidc_callback_mock(
    jwks_n: &str,
    jwks_kid: &str,
    token_kid: &str,
    _env: &std::sync::MutexGuard<'static, ()>,
) -> OidcCallbackMock {
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

    // RS256-signed ID token (iss/aud/exp/nonce match the mock issuer & flow)
    let id_token_claims = json!({
        "iss": issuer_url,
        "aud": "mock-client-id",
        "exp": (chrono::Utc::now().timestamp() + 3600),
        "nonce": "test-nonce-123",
        "preferred_username": "mock_alice",
        "roles": ["Onboarders"]
    });
    let id_token = sign_rs256_id_token(RSA_KEY_A_PEM, token_kid, &id_token_claims);

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

    // JWKS endpoint mock
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": jwks_kid,
                "n": jwks_n,
                "e": "AQAB",
            }]
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

    let flow_json = json!({
        "pkce_verifier": "test_pkce_verifier_string_12345678901234567890",
        "csrf_token": "test-csrf-state",
        "nonce": "test-nonce-123",
    })
    .to_string();

    OidcCallbackMock {
        app,
        _db: db,
        _server: mock_server,
        flow_cookie: format!("{OIDC_COOKIE_NAME}={flow_json}"),
    }
}

#[tokio::test]
async fn test_oidc_callback_verifies_id_token_signature_via_jwks() {
    // All three mock servers stay alive for the whole test: dropping one
    // could let a later MockServer::start reuse its port, and the URL-keyed
    // JWKS cache would then serve the earlier scenario's keys.
    //
    // Happy path: JWKS serves the RSA key matching the token's kid.
    let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mock_ok = setup_oidc_callback_mock(RSA_KEY_A_N, "test-key-1", "test-key-1", &_env).await;

    // CSRF state mismatch -> 400 before token exchange / verification
    let (status, _, _) = get_request(
        &mock_ok.app,
        "/auth/callback?code=mock_code&state=wrong-state",
        Some(&mock_ok.flow_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Valid signature -> 303 redirect to /me with session cookie set
    let (status, _, headers) = get_request(
        &mock_ok.app,
        "/auth/callback?code=mock_code&state=test-csrf-state",
        Some(&mock_ok.flow_cookie),
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

    // Unknown kid: no JWKS key matches even after the forced refresh -> 401
    let mock_kid_miss =
        setup_oidc_callback_mock(RSA_KEY_A_N, "test-key-1", "unknown-kid", &_env).await;
    let (status, body, _) = get_request(
        &mock_kid_miss.app,
        "/auth/callback?code=mock_code&state=test-csrf-state",
        Some(&mock_kid_miss.flow_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["raw"]
        .as_str()
        .unwrap_or_default()
        .contains("signing key not found"));

    // Wrong key: kid matches but the JWKS key did not sign the token -> 401
    let mock_wrong_key =
        setup_oidc_callback_mock(RSA_KEY_B_N, "test-key-1", "test-key-1", &_env).await;
    let (status, _, _) = get_request(
        &mock_wrong_key.app,
        "/auth/callback?code=mock_code&state=test-csrf-state",
        Some(&mock_wrong_key.flow_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
