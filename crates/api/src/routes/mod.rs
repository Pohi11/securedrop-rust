//! Router assembly: which URL maps to which handler, and which middleware wraps what.

mod health;
mod security;

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request},
    middleware::{from_fn, from_fn_with_state},
    response::IntoResponse,
    routing::{delete, get, post},
};
use tower::ServiceBuilder;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::{
    auth,
    error::AppError,
    files,
    middleware::{client_meta::REQUEST_ID_HEADER, rate_limit, request_id},
    shares,
    state::AppState,
    telemetry, users,
};

/// The API only ever receives small JSON documents (file bytes go straight to S3), so a tight
/// body limit costs nothing and removes a whole class of memory-exhaustion attacks.
/// The largest legitimate body is a 100-part presign request (~10 KB).
pub const MAX_BODY_BYTES: usize = 64 * 1024;

pub fn router(state: AppState) -> Router {
    // Unauthenticated, abuse-prone endpoints: strict per-IP limit.
    let public = Router::new()
        .route("/auth/register", post(auth::handlers::register))
        .route("/auth/login", post(auth::handlers::login))
        .route("/auth/refresh", post(auth::handlers::refresh))
        .route("/shared/download", post(shares::handlers::redeem))
        .route_layer(from_fn_with_state(state.clone(), rate_limit::limit_by_ip));

    // Authenticated API: per-user limit.
    let authed = Router::new()
        .route("/auth/logout", post(auth::handlers::logout))
        .route("/auth/logout-all", post(auth::handlers::logout_all))
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
        .route("/files/{id}/download", get(files::handlers::download))
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
        .route_layer(from_fn_with_state(state.clone(), rate_limit::limit_by_user));

    let api = Router::new().merge(public).merge(authed);

    let config = &state.config;
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .nest("/api/v1", api)
        .fallback(|| async { AppError::NotFound.into_response() })
        // Layers listed top-to-bottom run outermost-to-innermost on the request.
        .layer(
            ServiceBuilder::new()
                // Turn panics into a JSON 500 instead of a dropped connection.
                .layer(security::catch_panic())
                // Assign/propagate x-request-id before anything logs.
                .layer(from_fn(request_id::assign))
                // Mark Authorization/Cookie as sensitive so tracing never records them.
                .layer(security::sensitive_headers())
                // One span per request; every log line inside carries method, route, request id.
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(|req: &Request| {
                            let request_id = req
                                .headers()
                                .get(REQUEST_ID_HEADER)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default();
                            // Path only, never the query string.
                            tracing::info_span!(
                                "http",
                                method = %req.method(),
                                path = %req.uri().path(),
                                request_id,
                            )
                        })
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .layer(from_fn(telemetry::metrics::track_http))
                // Bound total handler time; slow dependencies can't pile up requests forever.
                .layer(security::timeout(config.http.request_timeout))
                .layer(security::cors(&config.http.cors_allowed_origins))
                .layer(security::SecurityHeaders::layer())
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .with_state(state)
}
