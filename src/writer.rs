//! Card-writer provisioning protocol.
//!
//! An admin-authenticated request creates a **single-use** provisioning job
//! (`jobs` table, TTL ≤ 120s). With a `uid` given, the fixed-uid job payload —
//! including the per-tag diversified key — is delivered on
//! `writer/{device_id}/job`, and only when the target device has role `writer`
//! or `both`. With no `uid`, a **wildcard** job is created and its empty
//! (`uid:"", key:""`) arming payload is delivered; the reader taps a tag and
//! publishes `writer/{device}/claim` with the observed uid, after which the
//! verifier binds the uid and republishes the keyed payload (see `mqtt.rs`).
//! The writer finalizes via `POST /v1/job/{job_id}/done` or
//! `writer/{device}/done`, which enrolls the tag (binds tag→member, sets
//! `last_counter` from the card's current counter).
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
pub const KEY_VERSION: i64 = 1;

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
    /// Target tag uid (16 hex). Absent or empty ⇒ wildcard job: the uid is
    /// bound on first `claim` from the reader.
    #[serde(default)]
    uid: Option<String>,
    member_key: String,
    device_id: String,
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
}

fn default_ttl() -> u64 {
    DEFAULT_TTL_SECS
}

/// Build the JSON delivery payload for a job. An empty `uid` is a wildcard
/// arming payload and carries no key.
pub fn job_payload(uid_hex: &str, key_hex: &str, job_id: &str, expires_at: &str) -> String {
    json!({
        "uid": uid_hex,
        "key": key_hex,
        "sun_config": {
            "key_version": KEY_VERSION,
            "cmac_bytes": SUN_CMAC_COMPARE_BYTES,
        },
        "job_id": job_id,
        "expires_at": expires_at,
    })
    .to_string()
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

    let is_wildcard = req.uid.as_deref().is_none_or(|u| u.is_empty());
    let (uid_hex, key_hex) = if is_wildcard {
        (String::new(), String::new())
    } else {
        let raw = req.uid.as_deref().unwrap_or("");
        let uid = match Uid::from_hex(raw) {
            Ok(u) => u,
            Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid uid"),
        };
        (
            raw.to_ascii_lowercase(),
            hex::encode(diversify(&state.master, &uid).0),
        )
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

    let payload = job_payload(&uid_hex, &key_hex, &job_id, &expires_at);

    state.jobs.publish_job(&req.device_id, &payload);

    (
        StatusCode::CREATED,
        Json(json!({ "job_id": job_id, "expires_at": expires_at })),
    )
        .into_response()
}

/// Outcome of consuming a job's completion (HTTP or MQTT `done` path).
#[derive(Debug)]
pub enum ConsumeOutcome {
    Enrolled { uid: String, member_key: String },
    AlreadyConsumed,
    Expired,
    NotFound,
    Error(String),
}

/// Finalize a job: single-use consume + enroll the tag, auditing the result.
/// Shared by `POST /v1/job/{id}/done` and the MQTT `writer/{device}/done`
/// handler. `device_hint` (the MQTT topic device) is advisory only.
pub fn consume_job(
    store: &mut Store,
    job_id: &str,
    counter: i64,
    now: &str,
    device_hint: Option<&str>,
) -> ConsumeOutcome {
    match store.take_job(job_id, now) {
        Ok(JobTake::Taken(job)) => {
            if let Some(hint) = device_hint {
                if hint != job.device_id {
                    tracing::warn!(job_id, hint, expected = %job.device_id, "done from unexpected device");
                }
            }
            if let Err(e) =
                store.enroll_job_tag(&job.uid, &job.member_key, KEY_VERSION, counter, now)
            {
                tracing::warn!(error = %e, "enroll_job_tag failed");
                return ConsumeOutcome::Error("store error".to_string());
            }
            let _ = store.audit_event(
                now,
                Some(&job.device_id),
                Some(&job.uid),
                Some(counter),
                "granted",
                "job_done",
            );
            ConsumeOutcome::Enrolled {
                uid: job.uid,
                member_key: job.member_key,
            }
        }
        Ok(JobTake::AlreadyConsumed(job)) => {
            let _ = store.audit_event(
                now,
                Some(&job.device_id),
                Some(&job.uid),
                Some(counter),
                "denied",
                "job_reused",
            );
            ConsumeOutcome::AlreadyConsumed
        }
        Ok(JobTake::Expired(job)) => {
            let _ = store.audit_event(
                now,
                Some(&job.device_id),
                Some(&job.uid),
                Some(counter),
                "denied",
                "job_expired",
            );
            ConsumeOutcome::Expired
        }
        Ok(JobTake::NotFound) => ConsumeOutcome::NotFound,
        Err(e) => {
            tracing::warn!(error = %e, "take_job failed");
            ConsumeOutcome::Error("store error".to_string())
        }
    }
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
    let mut store = state.store.lock().expect("store lock poisoned");
    match consume_job(&mut store, &job_id, req.counter as i64, &now, None) {
        ConsumeOutcome::Enrolled { uid, member_key } => (
            StatusCode::OK,
            Json(json!({ "enrolled": true, "uid": uid, "member_key": member_key })),
        )
            .into_response(),
        ConsumeOutcome::AlreadyConsumed => error_response(StatusCode::GONE, "job already consumed"),
        ConsumeOutcome::Expired => error_response(StatusCode::GONE, "job expired"),
        ConsumeOutcome::NotFound => error_response(StatusCode::NOT_FOUND, "unknown job"),
        ConsumeOutcome::Error(_) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "store error")
        }
    }
}
