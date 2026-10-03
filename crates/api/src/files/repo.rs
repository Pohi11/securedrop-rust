//! SQL for the `files` table.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use super::model::FileRecord;

pub struct NewFile<'a> {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub size_bytes: i64,
    pub sha256: &'a [u8],
    pub object_key: &'a str,
    pub upload_kind: &'a str,
    pub s3_upload_id: Option<&'a str>,
    pub part_size: Option<i64>,
    pub part_count: Option<i32>,
    pub upload_expires_at: DateTime<Utc>,
}

pub async fn insert(db: impl PgExecutor<'_>, f: NewFile<'_>) -> Result<FileRecord, sqlx::Error> {
    sqlx::query_as!(
        FileRecord,
        r#"INSERT INTO files (id, owner_id, filename, content_type, size_bytes, sha256, object_key,
                              upload_kind, s3_upload_id, part_size, part_count, upload_expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           RETURNING id, owner_id, filename, content_type, size_bytes, sha256, object_key, status,
                     upload_kind, s3_upload_id, part_size, part_count, s3_checksum,
                     upload_expires_at, created_at, completed_at"#,
        f.id,
        f.owner_id,
        f.filename,
        f.content_type,
        f.size_bytes,
        f.sha256,
        f.object_key,
        f.upload_kind,
        f.s3_upload_id,
        f.part_size,
        f.part_count,
        f.upload_expires_at
    )
    .fetch_one(db)
    .await
}

/// Fetch a file by id regardless of owner. Callers MUST run an authorization check on the
/// result before revealing anything about it (see `files::authz`).
pub async fn find_by_id(
    db: impl PgExecutor<'_>,
    id: Uuid,
) -> Result<Option<FileRecord>, sqlx::Error> {
    sqlx::query_as!(
        FileRecord,
        r#"SELECT id, owner_id, filename, content_type, size_bytes, sha256, object_key, status,
                  upload_kind, s3_upload_id, part_size, part_count, s3_checksum,
                  upload_expires_at, created_at, completed_at
           FROM files WHERE id = $1 AND status <> 'deleted'"#,
        id
    )
    .fetch_optional(db)
    .await
}

/// Transition pending -> available. The `status = 'pending'` guard makes this a compare-and-set:
/// if two "complete" calls race, exactly one wins and the other gets `None`.
pub async fn mark_available(
    db: impl PgExecutor<'_>,
    id: Uuid,
    s3_checksum: Option<&str>,
) -> Result<Option<FileRecord>, sqlx::Error> {
    sqlx::query_as!(
        FileRecord,
        r#"UPDATE files
           SET status = 'available', s3_checksum = $2, completed_at = now(), updated_at = now()
           WHERE id = $1 AND status = 'pending'
           RETURNING id, owner_id, filename, content_type, size_bytes, sha256, object_key, status,
                     upload_kind, s3_upload_id, part_size, part_count, s3_checksum,
                     upload_expires_at, created_at, completed_at"#,
        id,
        s3_checksum
    )
    .fetch_optional(db)
    .await
}

pub async fn mark_failed(db: impl PgExecutor<'_>, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"UPDATE files SET status = 'failed', updated_at = now()
           WHERE id = $1 AND status = 'pending'"#,
        id
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn mark_purged(db: impl PgExecutor<'_>, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!("UPDATE files SET purged_at = now() WHERE id = $1", id)
        .execute(db)
        .await?;
    Ok(())
}

/// Lock the user's row so concurrent upload requests from the same user serialise their
/// quota checks. Returns the user's quota.
pub async fn lock_user_quota(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT storage_quota_bytes FROM users WHERE id = $1 FOR UPDATE",
        user_id
    )
    .fetch_optional(db)
    .await
}

/// Record (or replace) the checksum a client declared for one part.
pub async fn upsert_part(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
    part_number: i32,
    sha256: &[u8],
    size_bytes: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"INSERT INTO upload_parts (file_id, part_number, sha256, size_bytes)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (file_id, part_number)
           DO UPDATE SET sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes"#,
        file_id,
        part_number,
        sha256,
        size_bytes
    )
    .execute(db)
    .await?;
    Ok(())
}

pub struct DeclaredPart {
    pub part_number: i32,
    pub sha256: Vec<u8>,
}

pub async fn declared_parts(
    db: impl PgExecutor<'_>,
    file_id: Uuid,
) -> Result<Vec<DeclaredPart>, sqlx::Error> {
    sqlx::query_as!(
        DeclaredPart,
        "SELECT part_number, sha256 FROM upload_parts WHERE file_id = $1 ORDER BY part_number",
        file_id
    )
    .fetch_all(db)
    .await
}

/// Minimal view of a file the cleanup worker needs.
pub struct CleanupTarget {
    pub id: Uuid,
    pub object_key: String,
    pub s3_upload_id: Option<String>,
}

/// Expire abandoned uploads: pending rows past their deadline become failed.
/// `FOR UPDATE SKIP LOCKED` lets several API replicas run the worker concurrently: each row is
/// claimed by exactly one of them, and nobody waits on another's locks.
pub async fn expire_pending(db: impl PgExecutor<'_>, limit: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        r#"UPDATE files SET status = 'failed', updated_at = now()
           WHERE id IN (
               SELECT id FROM files
               WHERE status = 'pending' AND upload_expires_at < now()
               ORDER BY upload_expires_at
               LIMIT $1
               FOR UPDATE SKIP LOCKED
           )"#,
        limit
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

/// Claim failed/deleted files whose storage has not been cleaned up yet.
pub async fn claim_unpurged(
    db: impl PgExecutor<'_>,
    limit: i64,
) -> Result<Vec<CleanupTarget>, sqlx::Error> {
    sqlx::query_as!(
        CleanupTarget,
        r#"SELECT id, object_key, s3_upload_id FROM files
           WHERE status IN ('failed', 'deleted') AND purged_at IS NULL
           ORDER BY updated_at
           LIMIT $1
           FOR UPDATE SKIP LOCKED"#,
        limit
    )
    .fetch_all(db)
    .await
}
