//! PostgreSQL connection pool and migrations.

use std::time::Duration;

use anyhow::Context;
use secrecy::ExposeSecret;
use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};

use crate::config::DatabaseConfig;

/// Migrations are embedded into the binary at compile time, so the deployed artifact always
/// carries exactly the schema it was built and tested against.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        // Fail requests quickly rather than queueing forever when the pool is exhausted.
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(10 * 60))
        .connect(config.url.expose_secret())
        .await
        .context("failed to connect to PostgreSQL")
}

/// Apply pending migrations. sqlx takes a Postgres advisory lock while migrating, so several
/// replicas starting at once will not race each other.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .context("failed to run database migrations")
}
