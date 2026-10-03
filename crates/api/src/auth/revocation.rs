//! Session revocation list in Redis.
//!
//! JWTs are stateless: once issued they are valid until `exp`. To support logout (and to kill
//! a stolen session immediately on refresh-token reuse) we keep a denylist of revoked session
//! ids. Entries only need to live as long as the longest-lived access token (the access TTL),
//! after which every token carrying that sid has expired anyway, so the list stays small.

use std::time::Duration;

use redis::{AsyncCommands, aio::ConnectionManager};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

#[derive(Clone)]
pub struct SessionRevocations {
    redis: ConnectionManager,
    prefix: String,
    ttl: Duration,
}

impl SessionRevocations {
    pub fn new(redis: ConnectionManager, key_prefix: &str, access_token_ttl: Duration) -> Self {
        Self {
            redis,
            prefix: format!("{key_prefix}revoked-session:"),
            // A little extra beyond the access TTL to cover the JWT leeway.
            ttl: access_token_ttl + Duration::from_secs(60),
        }
    }

    fn key(&self, session_id: Uuid) -> String {
        format!("{}{session_id}", self.prefix)
    }

    pub async fn revoke(&self, session_ids: &[Uuid]) -> AppResult<()> {
        if session_ids.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        for sid in session_ids {
            pipe.set_ex(self.key(*sid), 1u8, self.ttl.as_secs())
                .ignore();
        }
        let mut conn = self.redis.clone();
        pipe.query_async::<()>(&mut conn).await?;
        Ok(())
    }

    /// Fails closed: if Redis is unreachable we cannot prove the session is still valid, so
    /// the request is rejected with 503 rather than silently accepting a possibly-revoked token.
    pub async fn is_revoked(&self, session_id: Uuid) -> AppResult<bool> {
        let mut conn = self.redis.clone();
        conn.exists::<_, bool>(self.key(session_id))
            .await
            .map_err(|err| {
                tracing::error!(%err, "session revocation check failed; failing closed");
                AppError::Unavailable
            })
    }
}
