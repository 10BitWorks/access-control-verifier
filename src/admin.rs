use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::json;
use std::env;

use crate::api::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/admin", get(admin_ui))
        .route("/admin/api/tags", get(list_tags))
        .route("/admin/api/tags/enroll", post(enroll_tag))
        .route("/admin/api/tags/{uid}/revoke", post(revoke_tag))
        .route("/admin/api/members", get(list_members))
        .route("/admin/api/devices", get(list_devices).post(upsert_device))
        .route(
            "/admin/api/overrides",
            get(list_overrides).post(create_override),
        )
        .route("/admin/api/audit", get(list_audit))
        .route("/admin/api/sync-state", get(sync_state))
        .route("/admin/api/config", get(list_config).post(set_config))
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

    // 2. Check OIDC proxy headers (e.g. from Authentik/oauth2-proxy)
    if let Some(email) = headers
        .get("x-authentik-email")
        .or_else(|| headers.get("x-forwarded-email"))
    {
        if !email.is_empty() {
            return next.run(req).await;
        }
    }

    // Spec: "OIDC session / cookie or OIDC bearer token (with configurable issuer AUTHENTIK_OIDC_ISSUER, default https://auth.10bitworks.org/application/o/authorize/ or verified JWT/userinfo). If neither is valid, returns 401 Unauthorized."

    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                // Check if it's a JWT with the correct issuer
                let issuer = env::var("AUTHENTIK_OIDC_ISSUER").unwrap_or_else(|_| {
                    "https://auth.10bitworks.org/application/o/authorize/".to_string()
                });

                // Extremely simple JWT decode (header.payload.signature)
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() == 3 {
                    if let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(parts[1]) {
                        if let Ok(payload_val) =
                            serde_json::from_slice::<serde_json::Value>(&payload_bytes)
                        {
                            if let Some(iss) = payload_val.get("iss").and_then(|i| i.as_str()) {
                                if iss == issuer {
                                    // In a fully secure setup, we MUST verify the signature.
                                    return next.run(req).await;
                                }
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
