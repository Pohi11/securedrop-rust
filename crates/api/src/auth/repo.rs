//! SQL for `refresh_tokens`.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

#[derive(Debug)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct NewRefreshToken<'a> {
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub token_hash: &'a [u8],
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<&'a str>,
    pub client_ip: Option<&'a str>,
}

pub async fn insert(
    db: impl PgExecutor<'_>,
    new: NewRefreshToken<'_>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar!(
        r#"INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, user_agent, client_ip)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id"#,
        Uuid::now_v7(),
        new.user_id,
        new.family_id,
        new.token_hash,
        new.expires_at,
        new.user_agent,
        new.client_ip
    )
    .fetch_one(db)
    .await
}

/// Look up a token and lock its row for the rest of the transaction. Two concurrent refreshes
/// with the same token serialise here: the second one sees `used_at` set and is treated as reuse.
pub async fn find_for_update(
    db: impl PgExecutor<'_>,
    token_hash: &[u8],
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        RefreshTokenRow,
        r#"SELECT id, user_id, family_id, expires_at, used_at, revoked_at
           FROM refresh_tokens WHERE token_hash = $1
           FOR UPDATE"#,
        token_hash
    )
    .fetch_optional(db)
    .await
}

pub async fn mark_used(db: impl PgExecutor<'_>, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET used_at = now() WHERE id = $1",
        id
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn revoke_family(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
    family_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        r#"UPDATE refresh_tokens SET revoked_at = now()
           WHERE family_id = $1 AND user_id = $2 AND revoked_at IS NULL"#,
        family_id,
        user_id
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

/// Revoke every active session for a user; returns the affected session (family) ids.
pub async fn revoke_all_for_user(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"WITH revoked AS (
               UPDATE refresh_tokens SET revoked_at = now()
               WHERE user_id = $1 AND revoked_at IS NULL
               RETURNING family_id
           )
           SELECT DISTINCT family_id AS "family_id!" FROM revoked"#,
        user_id
    )
    .fetch_all(db)
    .await
}
