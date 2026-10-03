//! SecureDrop API library crate.
//!
//! `main.rs` is a thin wrapper around [`run`]; integration tests use [`build_app`] directly so
//! they exercise exactly the same router and middleware as production.

pub mod audit;
pub mod auth;
pub mod config;
pub mod database;
pub mod error;
pub mod extract;
pub mod files;
pub mod middleware;
pub mod routes;
pub mod state;
pub mod storage;
pub mod telemetry;
pub mod users;

use anyhow::Context;
use axum::Router;
use sqlx::PgPool;
use tokio::net::TcpListener;

use crate::{config::Config, state::AppState};

/// Connect to dependencies, run migrations and build the router.
pub async fn build_app(config: Config) -> anyhow::Result<(Router, AppState)> {
    let db = database::connect(&config.database).await?;
    database::migrate(&db).await?;
    build_app_with_pool(config, db).await
}

/// Like [`build_app`] but with an existing pool. Tests use this with the per-test database
/// that `#[sqlx::test]` creates (already migrated).
pub async fn build_app_with_pool(config: Config, db: PgPool) -> anyhow::Result<(Router, AppState)> {
    let state = AppState::new(config, db).await?;
    let router = routes::router(state.clone());
    Ok((router, state))
}

/// Run the server until SIGINT/SIGTERM, then drain in-flight requests.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let bind_addr = config.http.bind_addr;
    let (router, _state) = build_app(config).await?;

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;
    tracing::info!(%bind_addr, "securedrop-api listening");

    // ConnectInfo gives handlers/middleware the peer address (used for rate limiting).
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")
}

/// Resolves on Ctrl+C, or on SIGTERM (what ECS sends before stopping a task).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for ctrl-c");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => tracing::error!(%err, "failed to listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
