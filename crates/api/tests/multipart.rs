//! Phase 04: multipart, resumable uploads and the cleanup worker.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{TestApp, error_code, execute_presigned, sha256_hex};
use securedrop_api::files::cleanup;
use securedrop_common::{
    CreateUploadResponse, DownloadResponse, FileResponse, FileStatus, PresignPartsResponse,
    UploadInstructions, UploadProgressResponse,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const MIB: usize = 1024 * 1024;
const PART: usize = 5 * MIB; // S3's minimum part size

async fn spawn(pool: PgPool) -> TestApp {
    TestApp::spawn_with(pool, |c| {
        c.uploads.single_part_max = PART as u64;
        c.uploads.part_size = PART as u64;
    })
    .await
}

/// 12 MiB + 7 bytes of deterministic, non-executable data -> parts of 5, 5 and 2 MiB + 7.
fn test_data() -> Vec<u8> {
    let mut data = b"SecureDrop multipart test\n".to_vec();
    let mut x: u32 = 0x1234_5678;
    while data.len() < 12 * MIB + 7 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        data.push((x & 0xff) as u8);
    }
    data
}

fn parts_of(data: &[u8]) -> Vec<&[u8]> {
    data.chunks(PART).collect()
}

async fn start(app: &TestApp, token: &str, data: &[u8]) -> Uuid {
    let resp = app
        .create_upload(token, "big.bin", "application/octet-stream", data)
        .await;
    assert_eq!(resp.status(), 201);
    let created: CreateUploadResponse = resp.json().await.unwrap();
    match created.upload {
        UploadInstructions::Multipart {
            part_size,
            part_count,
        } => {
            assert_eq!(part_size, PART as u64);
            assert_eq!(part_count, 3);
        }
        UploadInstructions::Single { .. } => panic!("expected multipart"),
    }
    created.file_id
}

async fn presign(
    app: &TestApp,
    token: &str,
    file_id: Uuid,
    numbered: &[(u32, &[u8])],
) -> PresignPartsResponse {
    let parts: Vec<_> = numbered
        .iter()
        .map(|(n, bytes)| json!({ "part_number": n, "sha256": sha256_hex(bytes) }))
        .collect();
    let resp = app
        .post_authed(
            &format!("/api/v1/uploads/{file_id}/parts"),
            token,
            json!({ "parts": parts }),
        )
        .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    resp.json().await.unwrap()
}

async fn progress(app: &TestApp, token: &str, file_id: Uuid) -> UploadProgressResponse {
    app.get_authed(&format!("/api/v1/uploads/{file_id}/parts"), token)
        .await
        .json()
        .await
        .unwrap()
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn interrupted_upload_resumes_and_completes(pool: PgPool) {
    let app = spawn(pool).await;
    let token = app.signup("alice@example.com").await.access_token;
    let data = test_data();
    let parts = parts_of(&data);
    let file_id = start(&app, &token, &data).await;

    // First session: upload parts 1 and 3, then "crash" before part 2.
    let urls = presign(&app, &token, file_id, &[(1, parts[0]), (3, parts[2])]).await;
    for p in &urls.parts {
        let body = parts[(p.part_number - 1) as usize].to_vec();
        assert!(
            execute_presigned(&app.client, &p.request, Some(body))
                .await
                .status()
                .is_success()
        );
    }

    // Completing now is refused, but nothing is lost.
    let early = app.complete_upload(&token, file_id).await;
    assert_eq!(early.status(), 409);

    // A new session asks S3 (via the API) what's missing...
    let state = progress(&app, &token, file_id).await;
    assert_eq!(state.missing_parts, vec![2]);
    assert_eq!(state.uploaded_parts.len(), 2);

    // ...and uploads only that.
    let urls = presign(&app, &token, file_id, &[(2, parts[1])]).await;
    assert!(
        execute_presigned(&app.client, &urls.parts[0].request, Some(parts[1].to_vec()))
            .await
            .status()
            .is_success()
    );

    let resp = app.complete_upload(&token, file_id).await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let done: FileResponse = resp.json().await.unwrap();
    assert_eq!(done.status, FileStatus::Available);

    // Download and verify the whole-file SHA-256 the client declared at the start.
    let dl: DownloadResponse = app
        .get_authed(&format!("/api/v1/files/{file_id}/download"), &token)
        .await
        .json()
        .await
        .unwrap();
    let body = execute_presigned(&app.client, &dl.request, None)
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(body.len(), data.len());
    assert_eq!(sha256_hex(&body), sha256_hex(&data));
    assert_eq!(dl.sha256, sha256_hex(&data));
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn a_part_with_the_wrong_bytes_is_rejected_by_storage(pool: PgPool) {
    let app = spawn(pool).await;
    let token = app.signup("bob@example.com").await.access_token;
    let data = test_data();
    let parts = parts_of(&data);
    let file_id = start(&app, &token, &data).await;

    let urls = presign(&app, &token, file_id, &[(1, parts[0])]).await;
    let mut corrupted = parts[0].to_vec();
    corrupted[1000] ^= 0xff;
    let resp = execute_presigned(&app.client, &urls.parts[0].request, Some(corrupted)).await;
    assert!(
        resp.status().is_client_error(),
        "corrupted part accepted: {}",
        resp.status()
    );
    assert_eq!(
        progress(&app, &token, file_id).await.missing_parts,
        vec![1, 2, 3]
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn part_requests_are_validated(pool: PgPool) {
    let app = spawn(pool).await;
    let token = app.signup("carol@example.com").await.access_token;
    let data = test_data();
    let file_id = start(&app, &token, &data).await;

    for body in [
        json!({ "parts": [] }),
        json!({ "parts": [{ "part_number": 0, "sha256": "ab".repeat(32) }] }),
        json!({ "parts": [{ "part_number": 4, "sha256": "ab".repeat(32) }] }),
        json!({ "parts": [{ "part_number": 1, "sha256": "xyz" }] }),
    ] {
        let resp = app
            .post_authed(
                &format!("/api/v1/uploads/{file_id}/parts"),
                &token,
                body.clone(),
            )
            .await;
        assert_eq!(resp.status(), 422, "{body}");
    }

    // Part URLs make no sense for a single-part upload.
    let small = app
        .create_upload(&token, "s.txt", "text/plain", b"small")
        .await;
    let small: CreateUploadResponse = small.json().await.unwrap();
    let resp = app
        .post_authed(
            &format!("/api/v1/uploads/{}/parts", small.file_id),
            &token,
            json!({ "parts": [{ "part_number": 1, "sha256": "ab".repeat(32) }] }),
        )
        .await;
    assert_eq!(resp.status(), 409);

    // Another user can't touch this upload at all.
    let mallory = app.signup("mallory@example.com").await.access_token;
    assert_eq!(
        app.get_authed(&format!("/api/v1/uploads/{file_id}/parts"), &mallory)
            .await
            .status(),
        404
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn abort_releases_quota_and_storage(pool: PgPool) {
    let app = spawn(pool.clone()).await;
    let token = app.signup("dave@example.com").await.access_token;
    let data = test_data();
    let parts = parts_of(&data);
    let file_id = start(&app, &token, &data).await;
    let urls = presign(&app, &token, file_id, &[(1, parts[0])]).await;
    execute_presigned(&app.client, &urls.parts[0].request, Some(parts[0].to_vec())).await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/uploads/{file_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let (status, purged, key, upload_id): (String, bool, String, String) = sqlx::query_as(
        "SELECT status, purged_at IS NOT NULL, object_key, s3_upload_id FROM files WHERE id = $1",
    )
    .bind(file_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((status.as_str(), purged), ("failed", true));
    assert!(
        app.state
            .storage
            .list_parts(&key, &upload_id)
            .await
            .unwrap()
            .is_none(),
        "parts freed in S3"
    );

    // The reserved bytes no longer count against the quota.
    let me: securedrop_common::UserResponse = app
        .get_authed("/api/v1/me", &token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me.storage_used_bytes, 0);

    // Aborting twice is a conflict, not a crash.
    let again = app
        .client
        .delete(app.url(&format!("/api/v1/uploads/{file_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 409);
    assert_eq!(error_code(again).await, "conflict");
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn cleanup_worker_expires_abandoned_uploads(pool: PgPool) {
    let app = TestApp::spawn_with(pool.clone(), |c| {
        c.uploads.single_part_max = PART as u64;
        c.uploads.part_size = PART as u64;
        c.uploads.pending_upload_ttl = Duration::from_secs(1);
    })
    .await;
    let token = app.signup("erin@example.com").await.access_token;
    let data = test_data();
    let parts = parts_of(&data);
    let file_id = start(&app, &token, &data).await;
    let urls = presign(&app, &token, file_id, &[(1, parts[0])]).await;
    execute_presigned(&app.client, &urls.parts[0].request, Some(parts[0].to_vec())).await;

    // Not expired yet: nothing to do for this file.
    let stats = cleanup::run_once(&app.state).await.unwrap();
    assert_eq!(stats.expired, 0);

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let stats = cleanup::run_once(&app.state).await.unwrap();
    assert_eq!(stats.expired, 1);
    assert_eq!(stats.purged, 1);

    let (status, purged, key, upload_id): (String, bool, String, String) = sqlx::query_as(
        "SELECT status, purged_at IS NOT NULL, object_key, s3_upload_id FROM files WHERE id = $1",
    )
    .bind(file_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((status.as_str(), purged), ("failed", true));
    assert!(
        app.state
            .storage
            .list_parts(&key, &upload_id)
            .await
            .unwrap()
            .is_none()
    );

    // Idempotent: a second pass finds nothing.
    assert_eq!(
        cleanup::run_once(&app.state).await.unwrap(),
        cleanup::CleanupStats::default()
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn redeclaring_a_part_without_reuploading_fails_verification(pool: PgPool) {
    let app = spawn(pool).await;
    let token = app.signup("frank@example.com").await.access_token;
    let data = test_data();
    let parts = parts_of(&data);
    let file_id = start(&app, &token, &data).await;

    let urls = presign(
        &app,
        &token,
        file_id,
        &[(1, parts[0]), (2, parts[1]), (3, parts[2])],
    )
    .await;
    for p in &urls.parts {
        let body = parts[(p.part_number - 1) as usize].to_vec();
        assert!(
            execute_presigned(&app.client, &p.request, Some(body))
                .await
                .status()
                .is_success()
        );
    }
    // Now claim part 2 has different contents, but never upload them. The database's declared
    // hash and the stored part disagree; completion must notice even on stores whose ListParts
    // omits per-part checksums (the composite checksum catches it).
    let fake = vec![b'x'; parts[1].len()];
    presign(&app, &token, file_id, &[(2, &fake)]).await;

    let resp = app.complete_upload(&token, file_id).await;
    assert_eq!(resp.status(), 422, "{}", resp.text().await.unwrap());
}
