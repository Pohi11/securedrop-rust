//! SQL for the `users` table. Queries are checked against the real schema at compile time
//! by `sqlx::query!` / `query_as!` (or against `.sqlx/` offline data in CI and Docker).

use std::time::Duration;

use sqlx::PgExecutor;
use uuid::Uuid;

use super::model::User;

pub async fn insert(
    db: impl PgExecutor<'_>,
    id: Uuid,
    email: &str,
    password_hash: &str,
    quota: i64,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"INSERT INTO users (id, email, password_hash, storage_quota_bytes)
           VALUES ($1, $2, $3, $4)
           RETURNING id, email, password_hash, storage_quota_bytes, failed_login_count,
                     locked_until, created_at"#,
        id,
        email,
        password_hash,
        quota
    )
    .fetch_one(db)
    .await
}

pub async fn find_by_email(
    db: impl PgExecutor<'_>,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"SELECT id, email, password_hash, storage_quota_bytes, failed_login_count,
                  locked_until, created_at
           FROM users WHERE email = $1"#,
        email
    )
    .fetch_optional(db)
    .await
}

pub async fn find_by_id(db: impl PgExecutor<'_>, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"SELECT id, email, password_hash, storage_quota_bytes, failed_login_count,
                  locked_until, created_at
           FROM users WHERE id = $1"#,
        id
    )
    .fetch_optional(db)
    .await
}

/// Increment the failure counter atomically, locking the account once it reaches `max`.
/// Doing this in one UPDATE (not read-modify-write in Rust) means concurrent failed
/// attempts cannot race past the limit.
pub async fn record_failed_login(
    db: impl PgExecutor<'_>,
    id: Uuid,
    max: i32,
    lockout: Duration,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"UPDATE users
           SET failed_login_count = failed_login_count + 1,
               locked_until = CASE WHEN failed_login_count + 1 >= $2
                                   THEN now() + make_interval(secs => $3)
                                   ELSE locked_until END,
               updated_at = now()
           WHERE id = $1"#,
        id,
        max,
        lockout.as_secs_f64()
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn reset_failed_logins(db: impl PgExecutor<'_>, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = now()
           WHERE id = $1 AND (failed_login_count <> 0 OR locked_until IS NOT NULL)"#,
        id
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Bytes counted against the quota: completed files plus uploads still in progress
/// (otherwise a user could start many uploads in parallel and blow past their quota).
pub async fn storage_used(db: impl PgExecutor<'_>, id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT COALESCE(SUM(size_bytes), 0)::BIGINT AS "used!"
           FROM files WHERE owner_id = $1 AND status IN ('pending', 'available')"#,
        id
    )
    .fetch_one(db)
    .await
}
