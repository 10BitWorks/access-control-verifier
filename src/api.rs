use crate::crypto::{diversify, verify_sun, Key, SunCmac, TapCounter, Uid};
use crate::store::{AccessDecision, Store, TapOutcome};
use axum::{
    extract::{rejection::JsonRejection, Json, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};

pub const PULSE_MS: u32 = 300;
const MAX_COUNTER: u64 = 0xFF_FFFF;

pub trait DecisionSink: Send + Sync {
    fn publish_cmd(&self, reader: &str, grant: bool, reason: &str);
}

pub struct NoopSink;

impl DecisionSink for NoopSink {
    fn publish_cmd(&self, _reader: &str, _grant: bool, _reason: &str) {}
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub master: Key,
    pub secret: String,
    pub sink: Arc<dyn DecisionSink>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthRequest {
    reader: String,
    uid: String,
    counter: u64,
    cmac: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/auth", post(auth))
        .with_state(state)
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn map_store_reason(reason: &str) -> String {
    match reason {
        "tag_inactive" | "override_ban" => "override".to_string(),
        "unknown_member" | "member_inactive" => "member_inactive".to_string(),
        known @ ("ok" | "unknown_tag" | "bad_cmac" | "counter_replay") => known.to_string(),
        other => {
            tracing::warn!(reason = other, "unmapped access reason");
            "member_inactive".to_string()
        }
    }
}

async fn auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AuthRequest>, JsonRejection>,
) -> Response {
    let secret_ok = headers
        .get("x-emqx-secret")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == state.secret);
    if !secret_ok {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    let req = match payload {
        Ok(Json(r)) => r,
        Err(e) => {
            return error_response(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
        }
    };

    let uid = match Uid::from_hex(&req.uid) {
        Ok(u) => u,
        Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid uid"),
    };
    let cmac = match SunCmac::from_hex(&req.cmac) {
        Ok(c) => c,
        Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid cmac"),
    };
    if req.counter > MAX_COUNTER {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, "counter out of range");
    }

    let uid_hex = req.uid.to_ascii_lowercase();
    let now = chrono::Utc::now().to_rfc3339();
    let counter = req.counter as i64;

    let (grant, reason, name) = {
        let mut store = state.store.lock().expect("store lock poisoned");

        if !store.tag_exists(&uid_hex).unwrap_or(false) {
            let _ = store.record_tap(
                &uid_hex,
                counter,
                Some(&req.reader),
                &now,
                AccessDecision::Denied("unknown_tag".to_string()),
            );
            (false, "unknown_tag".to_string(), None)
        } else {
            let tag_key = diversify(&state.master, &uid);
            let tap_counter = TapCounter::from_u32(req.counter as u32);
            if verify_sun(&uid, &tap_counter, &cmac, &tag_key).is_err() {
                let _ = store.audit_event(
                    &now,
                    Some(&req.reader),
                    Some(&uid_hex),
                    Some(counter),
                    "denied",
                    "bad_cmac",
                );
                (false, "bad_cmac".to_string(), None)
            } else {
                let decision = store.effective_access(&uid_hex, &now).unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "effective_access failed");
                    AccessDecision::Denied("member_inactive".to_string())
                });
                let outcome = store
                    .record_tap(&uid_hex, counter, Some(&req.reader), &now, decision)
                    .unwrap_or_else(|e| {
                        tracing::warn!(error = %e, "record_tap failed");
                        TapOutcome::Denied("member_inactive".to_string())
                    });
                match outcome {
                    TapOutcome::Granted => {
                        let name = store.member_display_name(&uid_hex).ok().flatten();
                        (true, "ok".to_string(), name)
                    }
                    TapOutcome::Denied(r) => (false, map_store_reason(&r), None),
                }
            }
        }
    };

    state.sink.publish_cmd(&req.reader, grant, &reason);
    (
        StatusCode::OK,
        Json(json!({
            "grant": grant,
            "reason": reason,
            "name": name,
            "pulse_ms": PULSE_MS,
        })),
    )
        .into_response()
}
