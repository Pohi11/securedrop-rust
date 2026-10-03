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
