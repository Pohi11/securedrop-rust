//! Router assembly: which URL maps to which handler, and which middleware wraps what.

mod health;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{auth, files, shares, state::AppState, users};

pub fn router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(auth::handlers::register))
        .route("/login", post(auth::handlers::login))
        .route("/refresh", post(auth::handlers::refresh))
        .route("/logout", post(auth::handlers::logout))
        .route("/logout-all", post(auth::handlers::logout_all));

    let api = Router::new()
        .nest("/auth", auth_routes)
        .route("/me", get(users::handlers::me))
        .route("/uploads", post(files::handlers::create_upload))
        .route("/uploads/{id}", delete(files::handlers::abort_upload))
        .route(
            "/uploads/{id}/parts",
            get(files::handlers::upload_progress).post(files::handlers::presign_parts),
        )
        .route(
            "/uploads/{id}/complete",
            post(files::handlers::complete_upload),
        )
        .route("/files", get(files::handlers::list_files))
        .route(
            "/files/{id}",
            get(files::handlers::get_file).delete(files::handlers::delete_file),
        )
        .route(
            "/files/{id}/grants",
            get(shares::handlers::list_grants).post(shares::handlers::create_grant),
        )
        .route(
            "/files/{id}/grants/{user_id}",
            delete(shares::handlers::revoke_grant),
        )
        .route(
            "/files/{id}/share-links",
            get(shares::handlers::list_links).post(shares::handlers::create_link),
        )
        .route(
            "/files/{id}/share-links/{link_id}",
            delete(shares::handlers::revoke_link),
        )
        .route("/shared/download", post(shares::handlers::redeem))
        .route("/files/{id}/download", get(files::handlers::download));

    Router::new()
        .route("/healthz", get(health::liveness))
        .nest("/api/v1", api)
        .with_state(state)
}
