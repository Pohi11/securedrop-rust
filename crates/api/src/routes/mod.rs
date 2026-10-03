//! Router assembly: which URL maps to which handler, and which middleware wraps what.

mod health;

use axum::{Router, routing::get};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .with_state(state)
}
