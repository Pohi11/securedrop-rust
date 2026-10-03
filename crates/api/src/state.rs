//! Shared application state handed to every handler.
//!
//! `AppState` is cheap to clone (everything inside is an `Arc` or a pooled/multiplexed handle),
//! which is what Axum requires: the state is cloned for every request.

use std::sync::Arc;

use anyhow::Context;
use redis::aio::ConnectionManager;
use secrecy::ExposeSecret;
use sqlx::PgPool;

use crate::{
    auth::{jwt::JwtKeys, password::PasswordHasher, revocation::SessionRevocations},
    config::Config,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    /// Multiplexed, auto-reconnecting Redis connection (one TCP connection shared by all tasks).
    pub redis: ConnectionManager,
    pub jwt: JwtKeys,
    pub hasher: PasswordHasher,
    pub revocations: SessionRevocations,
}

impl AppState {
    pub async fn new(config: Config, db: PgPool) -> anyhow::Result<Self> {
        let redis_client =
            redis::Client::open(config.redis.url.expose_secret()).context("invalid REDIS_URL")?;
        let redis = ConnectionManager::new(redis_client)
            .await
            .context("failed to connect to Redis")?;

        // Bound concurrent Argon2 work to the number of CPUs (x2 to keep cores busy while a
        // blocking-pool thread is being scheduled).
        let cpus = std::thread::available_parallelism().map_or(2, |n| n.get());
        let hasher = PasswordHasher::new(cpus * 2)?;

        Ok(Self {
            jwt: JwtKeys::new(&config.auth),
            revocations: SessionRevocations::new(
                redis.clone(),
                &config.redis.key_prefix,
                config.auth.access_token_ttl,
            ),
            hasher,
            redis,
            db,
            config: Arc::new(config),
        })
    }
}
