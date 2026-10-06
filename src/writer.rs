//! Card-writer provisioning protocol.
//!
//! An admin-authenticated request creates a **single-use** provisioning job
//! (`jobs` table, TTL ≤ 120s). The job payload — including the per-tag
//! diversified key — is delivered only on `writer/{device_id}/job`, and only
//! when the target device has role `writer` or `both`. The writer consumes the
//! job via `POST /v1/job/{job_id}/done`, which finalizes enrollment (binds
//! tag→member, sets `last_counter` from the card's current counter).
//!
//! The master key never leaves this process: payloads carry only
//! `hex(diversify(master, uid))`.

use crate::crypto::{diversify, Key, Uid, SUN_CMAC_COMPARE_BYTES};
use crate::store::{JobTake, Store};
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use rumqttc::{AsyncClient, QoS};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};

pub const MAX_TTL_SECS: u64 = 120;
const DEFAULT_TTL_SECS: u64 = 120;
const MAX_COUNTER: u64 = 0xFF_FFFF;
const KEY_VERSION: i64 = 1;

/// Fire-and-forget delivery of provisioning jobs to writer devices.
pub trait JobPublisher: Send + Sync {
    fn publish_job(&self, device_id: &str, payload: &str);
}

pub struct NoopJobPublisher;

impl JobPublisher for NoopJobPublisher {
    fn publish_job(&self, _device_id: &str, _payload: &str) {}
}

pub struct MqttJobPublisher {
    client: AsyncClient,
}

impl MqttJobPublisher {
    pub fn new(client: AsyncClient) -> Self {
        Self { client }
    }
}

impl JobPublisher for MqttJobPublisher {
    fn publish_job(&self, device_id: &str, payload: &str) {
        // Jobs are single-use and short-lived: never retained on the broker.
        let topic = format!("writer/{device_id}/job");
        if let Err(e) = self
            .client
            .try_publish(topic, QoS::AtLeastOnce, false, payload)
        {
            tracing::warn!(error = %e, device_id, "job publish dropped");
        }
    }
}

#[derive(Clone)]
pub struct WriterState {
    pub store: Arc<Mutex<Store>>,
    pub master: Key,
    /// Static admin bearer token (env `ADMIN_BEARER_TOKEN`). Empty string
    /// fails closed: every create request is rejected.
    pub admin_token: String,
    pub jobs: Arc<dyn JobPublisher>,
}

pub fn router(state: WriterState) -> Router {
    Router::new()
        .route("/v1/jobs", post(create_job))
        .route("/v1/job/{job_id}", post(job_done))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateJobRequest {
    uid: String,
    member_key: String,
    device_id: String,
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
}

fn default_ttl() -> u64 {
    DEFAULT_TTL_SECS
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DoneRequest {
    counter: u64,
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn bearer_ok(headers: &HeaderMap, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.strip_prefix("Bearer ").is_some_and(|t| t == token))
}

async fn create_job(
    State(state): State<WriterState>,
    headers: HeaderMap,
    payload: Result<Json<CreateJobRequest>, JsonRejection>,
) -> Response {
    if !bearer_ok(&headers, &state.admin_token) {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let req = match payload {
        Ok(Json(r)) => r,
        Err(e) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
    };

    let uid = match Uid::from_hex(&req.uid) {
        Ok(u) => u,
        Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid uid"),
    };
    if req.member_key.is_empty() {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, "member_key required");
    }
    if req.ttl_secs == 0 || req.ttl_secs > MAX_TTL_SECS {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ttl_secs must be within 1..=120",
        );
    }

    let uid_hex = req.uid.to_ascii_lowercase();
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(req.ttl_secs as i64)).to_rfc3339();

    let job_id = {
        let mut store = state.store.lock().expect("store lock poisoned");
        let role = match store.device_role(&req.device_id) {
            Ok(Some(role)) => role,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "unknown device"),
            Err(e) => {
                tracing::warn!(error = %e, "device_role lookup failed");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "store error");
            }
        };
        if !matches!(role.as_str(), "writer" | "both") {
            return error_response(StatusCode::FORBIDDEN, "device is not a writer");
        }
        match store.create_job(
            &uid_hex,
            &req.member_key,
            &req.device_id,
            &now.to_rfc3339(),
            &expires_at,
        ) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %e, "create_job failed");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "store error");
            }
        }
    };

    let payload = json!({
        "uid": uid_hex,
        "key": hex::encode(diversify(&state.master, &uid).0),
        "sun_config": {
            "key_version": KEY_VERSION,
            "cmac_bytes": SUN_CMAC_COMPARE_BYTES,
        },
        "job_id": job_id,
        "expires_at": expires_at,
    })
    .to_string();

    state.jobs.publish_job(&req.device_id, &payload);

    (
        StatusCode::CREATED,
        Json(json!({ "job_id": job_id, "expires_at": expires_at })),
    )
        .into_response()
}

async fn job_done(
    State(state): State<WriterState>,
    Path(job_id): Path<String>,
    payload: Result<Json<DoneRequest>, JsonRejection>,
) -> Response {
    let req = match payload {
        Ok(Json(r)) => r,
        Err(e) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
    };
    if req.counter > MAX_COUNTER {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, "counter out of range");
    }

    let now = chrono::Utc::now().to_rfc3339();
    let counter = req.counter as i64;

    let mut store = state.store.lock().expect("store lock poisoned");
    match store.take_job(&job_id, &now) {
        Ok(JobTake::Taken(job)) => {
            if let Err(e) =
                store.enroll_job_tag(&job.uid, &job.member_key, KEY_VERSION, counter, &now)
            {
                tracing::warn!(error = %e, "enroll_job_tag failed");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "store error");
            }
            let _ = store.audit_event(
                &now,
                Some(&job.device_id),
                Some(&job.uid),
                Some(counter),
                "granted",
                "job_done",
            );
            (
                StatusCode::OK,
                Json(json!({ "enrolled": true, "uid": job.uid, "member_key": job.member_key })),
            )
                .into_response()
        }
        Ok(JobTake::AlreadyConsumed(job)) => {
            let _ = store.audit_event(
                &now,
                Some(&job.device_id),
                Some(&job.uid),
                Some(counter),
                "denied",
                "job_reused",
            );
            error_response(StatusCode::GONE, "job already consumed")
        }
        Ok(JobTake::Expired(job)) => {
            let _ = store.audit_event(
                &now,
                Some(&job.device_id),
                Some(&job.uid),
                Some(counter),
                "denied",
                "job_expired",
            );
            error_response(StatusCode::GONE, "job expired")
        }
        Ok(JobTake::NotFound) => error_response(StatusCode::NOT_FOUND, "unknown job"),
        Err(e) => {
            tracing::warn!(error = %e, "take_job failed");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "store error")
        }
    }
}
