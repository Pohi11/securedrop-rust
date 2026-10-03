//! The schema enforces its own invariants, independent of application code.
#![allow(clippy::unwrap_used)]

mod common;

use common::TestApp;
use sqlx::PgPool;
use uuid::Uuid;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

async fn insert_user(pool: &PgPool, email: &str, hash: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, password_hash, storage_quota_bytes) VALUES ($1, $2, $3, 1000)")
        .bind(id)
        .bind(email)
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(id)
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn emails_must_be_normalised_and_unique(pool: PgPool) {
    insert_user(&pool, "alice@example.com", HASH).await.unwrap();
    assert!(
        insert_user(&pool, "Bob@Example.com", HASH).await.is_err(),
        "uppercase rejected"
    );
    assert!(
        insert_user(&pool, " carol@example.com", HASH)
            .await
            .is_err(),
        "whitespace rejected"
    );
    assert!(
        insert_user(&pool, "alice@example.com", HASH).await.is_err(),
        "duplicate rejected"
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn password_hash_must_be_argon2id(pool: PgPool) {
    let err = insert_user(&pool, "dave@example.com", "plaintext-password").await;
    assert!(
        err.is_err(),
        "non-argon2id hashes are rejected by the database itself"
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn multipart_columns_must_be_consistent(pool: PgPool) {
    let owner = insert_user(&pool, "erin@example.com", HASH).await.unwrap();
    let insert = |kind: &'static str, upload_id: Option<&'static str>| {
        let pool = pool.clone();
        async move {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO files (id, owner_id, filename, content_type, size_bytes, sha256, object_key,
                                    upload_kind, s3_upload_id, upload_expires_at)
                 VALUES ($1, $2, 'a.txt', 'text/plain', 10, $3, $4, $5, $6, now())",
            )
            .bind(id)
            .bind(owner)
            .bind(vec![0u8; 32])
            .bind(format!("u/{owner}/{id}"))
            .bind(kind)
            .bind(upload_id)
            .execute(&pool)
            .await
        }
    };
    insert("single", None).await.unwrap();
    assert!(
        insert("single", Some("abc")).await.is_err(),
        "single upload cannot carry an upload id"
    );
    assert!(
        insert("multipart", None).await.is_err(),
        "multipart needs upload id + part info"
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn healthz_responds(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let resp = app.client.get(app.url("/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}
