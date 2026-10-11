pub mod admin;
pub mod api;
pub mod crypto;
pub mod mqtt;
pub mod store;
pub mod sync;
pub mod writer;

use axum::{routing::get, Router};

/// Assemble the HTTP router. `writer` mounts the card-writer provisioning API
/// (`/v1/jobs`, `/v1/job/{id}/done`) when present; tests and MQTT-only
/// deployments may pass `None`.
pub fn app(state: api::AppState, writer: Option<Router>) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(api::router(state.clone()))
        .merge(admin::router(state));
    if let Some(writer) = writer {
        router = router.merge(writer);
    }
    router
}
