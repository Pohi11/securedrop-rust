//! Phase 03: presigned single-part upload & download against a real S3-compatible store.
#![allow(clippy::unwrap_used)]

mod common;

use common::{TestApp, error_code, execute_presigned, sha256_hex};
use securedrop_common::{
    CreateUploadResponse, DownloadResponse, FileResponse, FileStatus, UploadInstructions,
};
use sqlx::PgPool;

async fn single_request(
    resp: reqwest::Response,
) -> (uuid::Uuid, securedrop_common::PresignedRequest) {
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let created: CreateUploadResponse = resp.json().await.unwrap();
    match created.upload {
        UploadInstructions::Single { request } => (created.file_id, request),
        UploadInstructions::Multipart { .. } => panic!("expected single-part"),
    }
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn upload_then_download_roundtrip(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let tokens = app.signup("alice@example.com").await;
    let data = b"hello, secure world\n".repeat(100);

    let (file_id, put) = single_request(
        app.create_upload(&tokens.access_token, "../../hello.txt", "text/plain", &data)
            .await,
    )
    .await;

    // The upload URL points at S3, not at our API, and the integrity headers are signed.
    assert!(!put.url.starts_with(&app.base_url));
    assert_eq!(put.method, "PUT");
    assert!(put.headers.contains_key("x-amz-checksum-sha256"));

    // Before the bytes arrive, the file is pending and cannot be downloaded or completed.
    let early = app.complete_upload(&tokens.access_token, file_id).await;
    assert_eq!(early.status(), 409);

    assert!(
        execute_presigned(&app.client, &put, Some(data.clone()))
            .await
            .status()
            .is_success()
    );
    let done: FileResponse = app
        .complete_upload(&tokens.access_token, file_id)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(done.status, FileStatus::Available);
    assert_eq!(done.filename, "hello.txt", "path components are stripped");
    assert_eq!(done.sha256, sha256_hex(&data));

    // Completing again is idempotent.
    assert_eq!(
        app.complete_upload(&tokens.access_token, file_id)
            .await
            .status(),
        200
    );

    let dl: DownloadResponse = app
        .get_authed(
            &format!("/api/v1/files/{file_id}/download"),
            &tokens.access_token,
        )
        .await
        .json()
        .await
        .unwrap();
    let resp = execute_presigned(&app.client, &dl.request, None).await;
    assert_eq!(resp.status(), 200);
    let disposition = resp.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(disposition.starts_with("attachment;"), "{disposition}");
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        sha256_hex(&body),
        dl.sha256,
        "downloaded bytes match the declared hash"
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn storage_rejects_bytes_that_do_not_match_the_declared_hash(pool: PgPool) {
    let app = TestApp::spawn(pool.clone()).await;
    let tokens = app.signup("bob@example.com").await;
    let declared = b"the real contents".to_vec();
    let (file_id, put) = single_request(
        app.create_upload(&tokens.access_token, "a.txt", "text/plain", &declared)
            .await,
    )
    .await;

    // Same length, different bytes: S3 itself must refuse it (BadDigest).
    let tampered = b"the fake contents".to_vec();
    assert_eq!(tampered.len(), declared.len());
    let put_resp = execute_presigned(&app.client, &put, Some(tampered)).await;
    assert!(
        put_resp.status().is_client_error(),
        "store accepted bytes with the wrong SHA-256"
    );

    // A bigger body sent honestly (with its real Content-Length) breaks the signature, because
    // Content-Length is one of the signed headers. A client cannot upload more than it declared
    // (and had reserved against its quota).
    let mut bigger = put.clone();
    let longer = b"the real contents, plus a lot of extra bytes".to_vec();
    bigger
        .headers
        .insert("content-length".into(), longer.len().to_string());
    let put_resp = execute_presigned(&app.client, &bigger, Some(longer)).await;
    assert_eq!(
        put_resp.status(),
        403,
        "store accepted a body of the wrong size"
    );

    // Nothing was stored, so completion is refused and the file stays pending.
    assert_eq!(
        app.complete_upload(&tokens.access_token, file_id)
            .await
            .status(),
        409
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn signed_headers_cannot_be_changed(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let tokens = app.signup("carol@example.com").await;
    let data = b"plain text".to_vec();
    let (_, mut put) = single_request(
        app.create_upload(&tokens.access_token, "a.txt", "text/plain", &data)
            .await,
    )
    .await;

    // Try to smuggle a different content type past the signature.
    put.headers
        .insert("content-type".into(), "text/html".into());
    let resp = execute_presigned(&app.client, &put, Some(data)).await;
    assert_eq!(resp.status(), 403, "signature must cover Content-Type");
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn executables_and_spoofed_types_are_rejected_on_completion(pool: PgPool) {
    let app = TestApp::spawn(pool.clone()).await;
    let tokens = app.signup("dave@example.com").await;

    for (name, content_type, data) in [
        (
            "notes.txt",
            "text/plain",
            b"\x7fELF\x02\x01\x01\x00 not really text".to_vec(),
        ),
        (
            "photo.png",
            "image/png",
            b"GIF89a pretending to be a png".to_vec(),
        ),
    ] {
        let (file_id, put) = single_request(
            app.create_upload(&tokens.access_token, name, content_type, &data)
                .await,
        )
        .await;
        assert!(
            execute_presigned(&app.client, &put, Some(data))
                .await
                .status()
                .is_success()
        );

        let resp = app.complete_upload(&tokens.access_token, file_id).await;
        assert_eq!(resp.status(), 422);
        assert_eq!(error_code(resp).await, "integrity_check_failed");

        // The row is failed and the object is gone from storage.
        let (status, purged): (String, bool) =
            sqlx::query_as("SELECT status, purged_at IS NOT NULL FROM files WHERE id = $1")
                .bind(file_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((status.as_str(), purged), ("failed", true));
        assert!(
            app.state
                .storage
                .head(&format!("u/{}/{file_id}", owner_of(&pool, file_id).await))
                .await
                .unwrap()
                .is_none()
        );
    }
}

async fn owner_of(pool: &PgPool, file_id: uuid::Uuid) -> uuid::Uuid {
    sqlx::query_scalar("SELECT owner_id FROM files WHERE id = $1")
        .bind(file_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn upload_request_validation(pool: PgPool) {
    let app = TestApp::spawn_with(pool, |c| c.uploads.max_file_size = 1024 * 1024).await;
    let t = app.signup("erin@example.com").await.access_token;

    let html = app
        .create_upload(&t, "x.html", "text/html", b"<script>")
        .await;
    assert_eq!(html.status(), 422, "text/html is not on the allowlist");

    let bad_hash = app
        .post_authed(
            "/api/v1/uploads",
            &t,
            serde_json::json!({ "filename": "a.txt", "content_type": "text/plain", "size_bytes": 3, "sha256": "nope" }),
        )
        .await;
    assert_eq!(bad_hash.status(), 422);

    let too_big = app
        .post_authed(
            "/api/v1/uploads",
            &t,
            serde_json::json!({ "filename": "a.bin", "content_type": "application/octet-stream",
                                "size_bytes": 2 * 1024 * 1024, "sha256": "ab".repeat(32) }),
        )
        .await;
    assert_eq!(too_big.status(), 413);

    let unauthenticated = app
        .client
        .post(app.url("/api/v1/uploads"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn quota_includes_pending_uploads(pool: PgPool) {
    let app = TestApp::spawn_with(pool, |c| c.uploads.default_user_quota = 100).await;
    let t = app.signup("frank@example.com").await.access_token;

    assert_eq!(
        app.create_upload(&t, "a.txt", "text/plain", &[b'a'; 60])
            .await
            .status(),
        201
    );
    // The first upload is still pending, but its 60 bytes are already reserved.
    let resp = app
        .create_upload(&t, "b.txt", "text/plain", &[b'b'; 60])
        .await;
    assert_eq!(resp.status(), 507);
    assert_eq!(error_code(resp).await, "quota_exceeded");
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn other_users_cannot_see_or_download_my_files(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let alice = app.signup("alice2@example.com").await.access_token;
    let mallory = app.signup("mallory@example.com").await.access_token;
    let file_id = app
        .upload_file(&alice, "secret.txt", "text/plain", b"top secret")
        .await;

    for path in [
        format!("/api/v1/files/{file_id}"),
        format!("/api/v1/files/{file_id}/download"),
    ] {
        let resp = app.get_authed(&path, &mallory).await;
        // 404, not 403: Mallory can't even learn that the file exists.
        assert_eq!(resp.status(), 404, "{path}");
    }
    assert_eq!(app.complete_upload(&mallory, file_id).await.status(), 404);

    let random = app
        .get_authed(&format!("/api/v1/files/{}", uuid::Uuid::now_v7()), &mallory)
        .await;
    assert_eq!(random.status(), 404);
    let garbage = app.get_authed("/api/v1/files/not-a-uuid", &mallory).await;
    assert_eq!(garbage.status(), 400);
}
