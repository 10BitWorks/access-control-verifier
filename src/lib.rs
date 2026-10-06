pub mod admin;
pub mod api;
pub mod crypto;
pub mod mqtt;
pub mod store;
pub mod sync;
pub mod writer;

use axum::{routing::get, Router};

pub fn app(state: api::AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(api::router(state.clone()))
        .merge(admin::router(state))
}
