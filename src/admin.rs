use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::env;
use subtle::ConstantTimeEq;

use crate::api::AppState;

pub fn router(state: AppState) -> Router {
    let api_routes = Router::new()
        .route("/tags", get(list_tags))
        .route("/tags/enroll", post(enroll_tag))
        .route("/tags/{uid}/revoke", post(revoke_tag))
        .route("/members", get(list_members))
        .route("/devices", get(list_devices).post(upsert_device))
        .route("/devices/{device_id}/role", post(set_device_role))
        .route("/jobs", post(arm_job))
        .route("/jobs/pending", get(pending_jobs))
        .route("/jobs/{job_id}", delete(cancel_job))
        .route("/overrides", get(list_overrides).post(create_override))
        .route("/audit", get(list_audit))
        .route("/sync-state", get(sync_state))
        .route("/sync", post(trigger_sync))
        .route("/config", get(list_config).post(set_config));

    Router::new()
        .route("/admin", get(admin_ui))
        .nest("/admin/api", api_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

async fn auth_middleware(
    State(_state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let bearer_token_env = env::var("ADMIN_BEARER_TOKEN").unwrap_or_default();

    // 1. Check Bearer Token directly matching ADMIN_BEARER_TOKEN
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if !bearer_token_env.is_empty() && token == bearer_token_env {
                    return next.run(req).await;
                }
            }
        }
    }

    // 2. Check Cookie matching admin_token=<token>
    if let Some(cookie_hdr) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("admin_token=") {
                    if !bearer_token_env.is_empty() && token == bearer_token_env {
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    // 3. Check query parameter ?token=<token>
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("token=") {
                if !bearer_token_env.is_empty() && token == bearer_token_env {
                    return next.run(req).await;
                }
            }
        }
    }

    // 4. Check trusted proxy header only if PROXY_AUTH_SECRET is configured and matches
    // WARNING: grants admin to ANY forwarded email when enabled — only for Authentik-forward-auth topologies; leave PROXY_AUTH_SECRET unset unless that is intended.
    if let (Some(email), Some(secret_hdr)) = (
        headers
            .get("x-authentik-email")
            .or_else(|| headers.get("x-forwarded-email")),
        headers.get("x-proxy-secret"),
    ) {
        let expected_secret = env::var("PROXY_AUTH_SECRET").unwrap_or_default();
        if !expected_secret.is_empty()
            && bool::from(secret_hdr.as_bytes().ct_eq(expected_secret.as_bytes()))
            && !email.is_empty()
        {
            return next.run(req).await;
        }
    }

    // 5. Check OIDC Portal session cookie
    let session_secret = env::var("SESSION_SECRET")
        .unwrap_or_else(|_| "insecure-dev-session-secret-change-me".to_string());
    let admin_role = env::var("ADMIN_ROLE").unwrap_or_else(|_| "Onboarder".to_string());

    if let Some(cookie_hdr) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(val) =
                    cookie.strip_prefix(&format!("{}=", crate::portal::SESSION_COOKIE_NAME))
                {
                    if let Some(principal) =
                        crate::portal::verify_session_token(val, &session_secret, &admin_role)
                    {
                        if principal.is_admin() {
                            return next.run(req).await;
                        } else {
                            tracing::warn!(
                                username = %principal.username,
                                roles = ?principal.roles,
                                expected_role = %admin_role,
                                "Admin access denied: user lacks required admin role"
                            );
                            // Logged-in non-admin gets a styled 403 on HTML or JSON error on API
                            let is_html_req = req.uri().path() == "/admin";
                            if is_html_req {
                                return (
                                    StatusCode::FORBIDDEN,
                                    Html(r#"<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title><style>body{font-family:sans-serif;margin:40px;line-height:1.5;}</style></head>
<body>
    <h1>403 Forbidden - Admin Access Required</h1>
    <p>You are signed in as <strong>admin-restricted user</strong>, but your account lacks the required admin role.</p>
    <p><a href="/me">Return to Self-Service Key Portal</a></p>
</body>
</html>"#),
                                ).into_response();
                            } else {
                                return (
                                    StatusCode::FORBIDDEN,
                                    Json(json!({"error": "forbidden: admin role required"})),
                                )
                                    .into_response();
                            }
                        }
                    }
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

async fn admin_ui() -> Html<&'static str> {
    Html(include_str!("admin.html"))
}

async fn list_tags(State(state): State<AppState>) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    match store.list_tags() {
        Ok(tags) => (StatusCode::OK, Json(tags)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct EnrollRequest {
    uid: String,
    member_key: String,
    key_version: i64,
}

async fn enroll_tag(State(state): State<AppState>, Json(req): Json<EnrollRequest>) -> Response {
    let mut store = state.store.lock().expect("store lock poisoned");
    let now = chrono::Utc::now().to_rfc3339();
    match store.enroll_tag(&req.uid, &req.member_key, req.key_version, &now) {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn revoke_tag(State(state): State<AppState>, Path(uid): Path<String>) -> Response {
    let mut store = state.store.lock().expect("store lock poisoned");
    match store.revoke_tag(&uid) {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn list_members(State(state): State<AppState>) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    match store.list_members() {
        Ok(members) => (StatusCode::OK, Json(members)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn list_devices(State(state): State<AppState>) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    match store.list_devices() {
        Ok(devices) => (StatusCode::OK, Json(devices)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DeviceUpsert {
    device_id: String,
    role: String,
    offline_verify: bool,
}

async fn upsert_device(State(state): State<AppState>, Json(req): Json<DeviceUpsert>) -> Response {
    let mut store = state.store.lock().expect("store lock poisoned");
    match store.upsert_device(&req.device_id, &req.role, req.offline_verify) {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn set_device_role(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Json(req): Json<RoleSet>,
) -> Response {
    let mut store = state.store.lock().expect("store lock poisoned");
    match store.set_device_role(&device_id, &req.role) {
        Ok(true) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown device or invalid role"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RoleSet {
    role: String,
}

// ---------------------------------------------------------------------------
// Provisioning (T6): arm writer jobs / pending list / cancel — same writer
// protocol as `writer::create_job`, but behind the admin middleware so an
// Authentik-proxied browser session can drive it.
// ---------------------------------------------------------------------------

use crate::writer::job_payload;
use crate::{crypto::diversify, writer::MAX_TTL_SECS};

#[derive(Deserialize)]
struct ArmJobRequest {
    /// Absent/empty ⇒ wildcard job (uid bound on first claim).
    #[serde(default)]
    uid: Option<String>,
    member_key: String,
    device_id: String,
    #[serde(default = "default_arm_ttl")]
    ttl_secs: u64,
}

fn default_arm_ttl() -> u64 {
    // Mirrors writer::DEFAULT_TTL_SECS (private there).
    120
}

async fn arm_job(State(state): State<AppState>, Json(req): Json<ArmJobRequest>) -> Response {
    // Mirrors writer::create_job's validation exactly.
    let is_wildcard = req.uid.as_deref().is_none_or(|u| u.is_empty());
    let (uid_hex, key_hex) = if is_wildcard {
        (String::new(), String::new())
    } else {
        let raw = req.uid.as_deref().unwrap_or("");
        let uid = match crate::crypto::Uid::from_hex(raw) {
            Ok(u) => u,
            Err(_) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({"error": "invalid uid"})),
                )
                    .into_response()
            }
        };
        (
            raw.to_ascii_lowercase(),
            hex::encode(diversify(&state.master, &uid).0),
        )
    };
    if req.member_key.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "member_key required"})),
        )
            .into_response();
    }
    if req.ttl_secs == 0 || req.ttl_secs > MAX_TTL_SECS {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "ttl_secs must be within 1..=120"})),
        )
            .into_response();
    }

    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(req.ttl_secs as i64)).to_rfc3339();

    let job_id = {
        let mut store = state.store.lock().expect("store lock poisoned");
        let role = match store.device_role(&req.device_id) {
            Ok(Some(role)) => role,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "unknown device"})),
                )
                    .into_response()
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "store error"})),
                )
                    .into_response()
            }
        };
        if !matches!(role.as_str(), "writer" | "both") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "device is not a writer"})),
            )
                .into_response();
        }
        match store.create_job(
            &uid_hex,
            &req.member_key,
            &req.device_id,
            &now.to_rfc3339(),
            &expires_at,
        ) {
            Ok(id) => id,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "store error"})),
                )
                    .into_response()
            }
        }
    };

    let payload = job_payload(&uid_hex, &key_hex, &job_id, &expires_at);
    state.jobs.publish_job(&req.device_id, &payload);

    (
        StatusCode::CREATED,
        Json(json!({ "job_id": job_id, "expires_at": expires_at })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct PendingQuery {
    device: Option<String>,
}

async fn pending_jobs(
    State(state): State<AppState>,
    Query(query): Query<PendingQuery>,
) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    let now = chrono::Utc::now().to_rfc3339();
    match store.pending_jobs(query.device.as_deref(), &now) {
        Ok(jobs) => (StatusCode::OK, Json(jobs)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn cancel_job(State(state): State<AppState>, Path(job_id): Path<String>) -> Response {
    let mut store = state.store.lock().expect("store lock poisoned");
    let now = chrono::Utc::now().to_rfc3339();
    // Only a live (pending) job can be cancelled — `fail_job` alone would
    // happily re-consume and re-audit an already-consumed job.
    let live = store
        .pending_jobs(None, &now)
        .map(|jobs| jobs.iter().any(|j| j.job_id == job_id))
        .unwrap_or(false);
    if !live {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown or already-consumed job"})),
        )
            .into_response();
    }
    match store.fail_job(&job_id, &now, "cancelled") {
        Ok(true) => (StatusCode::OK, Json(json!({"status": "cancelled"}))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown or already-consumed job"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn list_overrides(State(state): State<AppState>) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    match store.list_overrides() {
        Ok(overrides) => (StatusCode::OK, Json(overrides)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct OverrideCreate {
    member_key: Option<String>,
    uid: Option<String>,
    kind: String,
    expires_at: Option<String>,
    note: Option<String>,
}

async fn create_override(
    State(state): State<AppState>,
    Json(req): Json<OverrideCreate>,
) -> Response {
    let mut store = state.store.lock().expect("store lock poisoned");
    let now = chrono::Utc::now().to_rfc3339();
    match store.create_override(
        req.member_key.as_deref(),
        req.uid.as_deref(),
        &req.kind,
        req.expires_at.as_deref(),
        req.note.as_deref(),
        &now,
    ) {
        Ok(id) => (StatusCode::OK, Json(json!({"id": id}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
    uid: Option<String>,
    decision: Option<String>,
}

async fn list_audit(State(state): State<AppState>, Query(query): Query<AuditQuery>) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    match store.list_audit(
        query.limit.unwrap_or(50),
        query.uid.as_deref(),
        query.decision.as_deref(),
    ) {
        Ok(audit) => (StatusCode::OK, Json(audit)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn sync_state(State(state): State<AppState>) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    match store.sync_state() {
        Ok(Some(s)) => (StatusCode::OK, Json(s)).into_response(),
        Ok(None) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn trigger_sync(State(state): State<AppState>) -> Response {
    let sync_cfg = match crate::sync::SyncConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Sync config error: {e}")})),
            )
                .into_response();
        }
    };
    match crate::sync::run_sync_cycle(state.store.clone(), &sync_cfg).await {
        Ok(stats) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "added_or_updated": stats.added_or_updated,
                "removed": stats.removed,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn list_config(State(state): State<AppState>) -> Response {
    let store = state.store.lock().expect("store lock poisoned");
    match store.list_config() {
        Ok(cfg) => (StatusCode::OK, Json(cfg)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ConfigSet {
    key: String,
    value: String,
}

async fn set_config(State(state): State<AppState>, Json(req): Json<ConfigSet>) -> Response {
    let mut store = state.store.lock().expect("store lock poisoned");
    match store.set_config(&req.key, &req.value) {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
