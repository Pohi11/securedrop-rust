//! Shared application state handed to every handler.
//!
//! `AppState` is cheap to clone (everything inside is an `Arc` or a pooled handle), which is
//! what Axum requires: the state is cloned for every request.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
}

impl AppState {
    pub fn new(config: Config, db: PgPool) -> Self {
        Self {
            config: Arc::new(config),
            db,
        }
    }
}
