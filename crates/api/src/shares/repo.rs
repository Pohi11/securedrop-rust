//! SQL for `file_grants` and `share_links`.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

pub async fn has_grant(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM file_grants WHERE file_id = $1 AND grantee_id = $2) AS "exists!""#,
        file_id,
        user_id
    )
    .fetch_one(db)
    .await
}

pub async fn insert_grant(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
    grantee_id: Uuid,
    granted_by: Uuid,
) -> Result<DateTime<Utc>, sqlx::Error> {
    // Upsert so granting twice is idempotent; returns the original grant time.
    sqlx::query_scalar!(
        r#"INSERT INTO file_grants (file_id, grantee_id, granted_by) VALUES ($1, $2, $3)
           ON CONFLICT (file_id, grantee_id) DO UPDATE SET file_id = EXCLUDED.file_id
           RETURNING created_at"#,
        file_id,
        grantee_id,
        granted_by
    )
    .fetch_one(db)
    .await
}

pub async fn delete_grant(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
    grantee_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM file_grants WHERE file_id = $1 AND grantee_id = $2",
        file_id,
        grantee_id
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub struct GrantRow {
    pub user_id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

pub async fn list_grants(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
) -> Result<Vec<GrantRow>, sqlx::Error> {
    sqlx::query_as!(
        GrantRow,
        r#"SELECT u.id AS user_id, u.email, g.created_at
           FROM file_grants g JOIN users u ON u.id = g.grantee_id
           WHERE g.file_id = $1
           ORDER BY g.created_at"#,
        file_id
    )
    .fetch_all(db)
    .await
}

pub struct ShareLinkRow {
    pub id: Uuid,
    pub file_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub max_downloads: Option<i32>,
    pub download_count: i32,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_link(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
    created_by: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
    max_downloads: Option<i32>,
) -> Result<ShareLinkRow, sqlx::Error> {
    sqlx::query_as!(
        ShareLinkRow,
        r#"INSERT INTO share_links (id, file_id, created_by, token_hash, expires_at, max_downloads)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, file_id, expires_at, max_downloads, download_count, revoked_at, created_at"#,
        Uuid::now_v7(),
        file_id,
        created_by,
        token_hash,
        expires_at,
        max_downloads
    )
    .fetch_one(db)
    .await
}

pub async fn list_links(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
) -> Result<Vec<ShareLinkRow>, sqlx::Error> {
    sqlx::query_as!(
        ShareLinkRow,
        r#"SELECT id, file_id, expires_at, max_downloads, download_count, revoked_at, created_at
           FROM share_links WHERE file_id = $1 ORDER BY created_at DESC"#,
        file_id
    )
    .fetch_all(db)
    .await
}

pub async fn revoke_link(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
    link_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"UPDATE share_links SET revoked_at = now()
           WHERE id = $1 AND file_id = $2 AND revoked_at IS NULL"#,
        link_id,
        file_id
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Atomically validate a share token and consume one download.
///
/// All conditions live in the WHERE clause of a single UPDATE, so the check and the increment
/// cannot be separated by a race: with `max_downloads = 5` and 100 concurrent requests,
/// exactly 5 rows are returned. (A SELECT-then-UPDATE in application code would let all 100
/// read `download_count = 0` and succeed.)
pub async fn redeem_link(
    db: impl PgExecutor<'_>,
    token_hash: &[u8],
) -> Result<Option<(Uuid, Uuid)>, sqlx::Error> {
    let row = sqlx::query!(
        r#"UPDATE share_links SET download_count = download_count + 1
           WHERE token_hash = $1
             AND revoked_at IS NULL
             AND expires_at > now()
             AND (max_downloads IS NULL OR download_count < max_downloads)
             AND EXISTS (SELECT 1 FROM files f WHERE f.id = share_links.file_id AND f.status = 'available')
           RETURNING id, file_id"#,
        token_hash
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| (r.id, r.file_id)))
}
