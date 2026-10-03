//! Router assembly: which URL maps to which handler, and which middleware wraps what.

mod health;

use axum::{
    Router,
    routing::{get, post},
};

use crate::{auth, state::AppState, users};

pub fn router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(auth::handlers::register))
        .route("/login", post(auth::handlers::login))
        .route("/refresh", post(auth::handlers::refresh))
        .route("/logout", post(auth::handlers::logout))
        .route("/logout-all", post(auth::handlers::logout_all));

    let api = Router::new()
        .nest("/auth", auth_routes)
        .route("/me", get(users::handlers::me));

    Router::new()
        .route("/healthz", get(health::liveness))
        .nest("/api/v1", api)
        .with_state(state)
}
