pub mod admin;
pub mod api;
pub mod crypto;
pub mod mqtt;
pub mod store;
pub mod sync;
pub mod writer;

use axum::{routing::get, Router};

pub fn app() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}
