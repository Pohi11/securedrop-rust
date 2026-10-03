//! Phase 05: authorization, grants, share links, listing and deletion.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{TestApp, error_code, execute_presigned, sha256_hex};
use securedrop_common::{
    CreatedShareLinkResponse, DownloadResponse, FileListResponse, GrantResponse, UserResponse,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

// Small helpers local to this file.

async fn delete(app: &TestApp, path: &str, token: &str) -> reqwest::Response {
    app.client
        .delete(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn redeem(app: &TestApp, token: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/shared/download"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap()
}

async fn create_link(
    app: &TestApp,
    owner: &str,
    file_id: Uuid,
    body: serde_json::Value,
) -> CreatedShareLinkResponse {
    let resp = app
        .post_authed(&format!("/api/v1/files/{file_id}/share-links"), owner, body)
        .await;
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    resp.json().await.unwrap()
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn grants_give_read_only_access(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let bob = app.signup("bob@example.com").await.access_token;
    let mallory = app.signup("mallory@example.com").await.access_token;
    let file_id = app
        .upload_file(&alice, "plan.txt", "text/plain", b"the plan")
        .await;

    let resp = app
        .post_authed(
            &format!("/api/v1/files/{file_id}/grants"),
            &alice,
            json!({ "email": "BOB@example.com" }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let grant: GrantResponse = resp.json().await.unwrap();
    assert_eq!(grant.email, "bob@example.com");

    // Bob sees it under "shared with me" and can download it.
    let shared: FileListResponse = app
        .get_authed("/api/v1/files?scope=shared", &bob)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(shared.files.len(), 1);
    assert_eq!(shared.files[0].id, file_id);
    let dl: DownloadResponse = app
        .get_authed(&format!("/api/v1/files/{file_id}/download"), &bob)
        .await
        .json()
        .await
        .unwrap();
    let body = execute_presigned(&app.client, &dl.request, None)
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(&body[..], b"the plan");

    // Bob can't delete, re-share, or manage it. He knows it exists, so 403 is fine for him.
    assert_eq!(
        delete(&app, &format!("/api/v1/files/{file_id}"), &bob)
            .await
            .status(),
        403
    );
    let reshare = app
        .post_authed(
            &format!("/api/v1/files/{file_id}/grants"),
            &bob,
            json!({ "email": "mallory@example.com" }),
        )
        .await;
    assert_eq!(reshare.status(), 403);
    let link = app
        .post_authed(
            &format!("/api/v1/files/{file_id}/share-links"),
            &bob,
            json!({}),
        )
        .await;
    assert_eq!(link.status(), 403);

    // Mallory has no relation to the file at all: 404 everywhere.
    for path in [
        format!("/api/v1/files/{file_id}"),
        format!("/api/v1/files/{file_id}/download"),
        format!("/api/v1/files/{file_id}/grants"),
    ] {
        assert_eq!(
            app.get_authed(&path, &mallory).await.status(),
            404,
            "{path}"
        );
    }

    // Revoking the grant removes Bob's access immediately.
    let me: UserResponse = app
        .get_authed("/api/v1/me", &bob)
        .await
        .json()
        .await
        .unwrap();
    let resp = delete(
        &app,
        &format!("/api/v1/files/{file_id}/grants/{}", me.id),
        &alice,
    )
    .await;
    assert_eq!(resp.status(), 204);
    assert_eq!(
        app.get_authed(&format!("/api/v1/files/{file_id}/download"), &bob)
            .await
            .status(),
        404
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn grant_validation(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let file_id = app.upload_file(&alice, "a.txt", "text/plain", b"a").await;

    let unknown = app
        .post_authed(
            &format!("/api/v1/files/{file_id}/grants"),
            &alice,
            json!({ "email": "ghost@example.com" }),
        )
        .await;
    assert_eq!(unknown.status(), 422);
    let me = app
        .post_authed(
            &format!("/api/v1/files/{file_id}/grants"),
            &alice,
            json!({ "email": "alice@example.com" }),
        )
        .await;
    assert_eq!(me.status(), 422);

    // Pending (not yet completed) uploads can't be shared.
    let pending = app
        .create_upload(&alice, "p.txt", "text/plain", b"pending")
        .await;
    let pending: securedrop_common::CreateUploadResponse = pending.json().await.unwrap();
    let resp = app
        .post_authed(
            &format!("/api/v1/files/{}/share-links", pending.file_id),
            &alice,
            json!({}),
        )
        .await;
    assert_eq!(resp.status(), 409);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn share_links_work_anonymously_and_respect_limits(pool: PgPool) {
    let app = TestApp::spawn(pool.clone()).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let data = b"shared via link".to_vec();
    let file_id = app
        .upload_file(&alice, "doc.txt", "text/plain", &data)
        .await;

    let created = create_link(&app, &alice, file_id, json!({ "max_downloads": 2 })).await;
    assert_eq!(created.link.max_downloads, Some(2));

    // Only the hash of the token is stored.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM share_links WHERE id = $1")
        .bind(created.link.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, created.token.as_bytes());

    // No Authorization header at all.
    for _ in 0..2 {
        let resp = redeem(&app, &created.token).await;
        assert_eq!(resp.status(), 200);
        let dl: DownloadResponse = resp.json().await.unwrap();
        let body = execute_presigned(&app.client, &dl.request, None)
            .await
            .bytes()
            .await
            .unwrap();
        assert_eq!(sha256_hex(&body), sha256_hex(&data));
    }
    let exhausted = redeem(&app, &created.token).await;
    assert_eq!(exhausted.status(), 404);

    // Wrong token: same 404 as an exhausted one.
    assert_eq!(redeem(&app, "not-a-real-token").await.status(), 404);

    let links: Vec<securedrop_common::ShareLinkResponse> = app
        .get_authed(&format!("/api/v1/files/{file_id}/share-links"), &alice)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(links[0].download_count, 2);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn share_links_expire_and_can_be_revoked(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let file_id = app.upload_file(&alice, "doc.txt", "text/plain", b"x").await;

    let short = create_link(&app, &alice, file_id, json!({ "expires_in_secs": 1 })).await;
    let revocable = create_link(&app, &alice, file_id, json!({})).await;

    assert_eq!(redeem(&app, &revocable.token).await.status(), 200);
    let resp = delete(
        &app,
        &format!("/api/v1/files/{file_id}/share-links/{}", revocable.link.id),
        &alice,
    )
    .await;
    assert_eq!(resp.status(), 204);
    assert_eq!(redeem(&app, &revocable.token).await.status(), 404);

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(redeem(&app, &short.token).await.status(), 404);

    for bad in [
        json!({ "expires_in_secs": 0 }),
        json!({ "expires_in_secs": 8 * 24 * 3600 }),
        json!({ "max_downloads": 0 }),
    ] {
        let resp = app
            .post_authed(
                &format!("/api/v1/files/{file_id}/share-links"),
                &alice,
                bad.clone(),
            )
            .await;
        assert_eq!(resp.status(), 422, "{bad}");
    }
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn download_limit_holds_under_concurrency(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let file_id = app.upload_file(&alice, "doc.txt", "text/plain", b"x").await;
    let created = create_link(&app, &alice, file_id, json!({ "max_downloads": 5 })).await;

    // 25 simultaneous redemptions of a 5-download link.
    let tasks: Vec<_> = (0..25)
        .map(|_| {
            let client = app.client.clone();
            let url = app.url("/api/v1/shared/download");
            let token = created.token.clone();
            tokio::spawn(async move {
                client
                    .post(url)
                    .json(&json!({ "token": token }))
                    .send()
                    .await
                    .unwrap()
                    .status()
            })
        })
        .collect();
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, 5, "exactly max_downloads redemptions may succeed");
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn deleting_a_file_removes_access_storage_and_quota(pool: PgPool) {
    let app = TestApp::spawn(pool.clone()).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let file_id = app
        .upload_file(&alice, "gone.txt", "text/plain", b"soon gone")
        .await;
    let link = create_link(&app, &alice, file_id, json!({})).await;

    assert_eq!(
        delete(&app, &format!("/api/v1/files/{file_id}"), &alice)
            .await
            .status(),
        204
    );

    assert_eq!(
        app.get_authed(&format!("/api/v1/files/{file_id}"), &alice)
            .await
            .status(),
        404
    );
    assert_eq!(redeem(&app, &link.token).await.status(), 404);
    let me: UserResponse = app
        .get_authed("/api/v1/me", &alice)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me.storage_used_bytes, 0);

    let key: String = sqlx::query_scalar("SELECT object_key FROM files WHERE id = $1")
        .bind(file_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(app.state.storage.head(&key).await.unwrap().is_none());

    // The audit trail survives the deletion.
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_events WHERE target_id = $1 ORDER BY id")
            .bind(file_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(actions.contains(&"file.deleted".to_string()));
    assert!(actions.contains(&"file.upload_completed".to_string()));

    let again = delete(&app, &format!("/api/v1/files/{file_id}"), &alice).await;
    assert_eq!(again.status(), 404);
    assert_eq!(error_code(again).await, "not_found");
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn listing_is_paginated_and_scoped(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let bob = app.signup("bob@example.com").await.access_token;
    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(
            app.upload_file(
                &alice,
                &format!("f{i}.txt"),
                "text/plain",
                format!("file {i}").as_bytes(),
            )
            .await,
        );
    }
    app.upload_file(&bob, "bobs.txt", "text/plain", b"bob")
        .await;

    let page1: FileListResponse = app
        .get_authed("/api/v1/files?limit=2", &alice)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        page1.files.iter().map(|f| f.id).collect::<Vec<_>>(),
        vec![ids[2], ids[1]],
        "newest first"
    );
    let cursor = page1.next_cursor.unwrap();
    let page2: FileListResponse = app
        .get_authed(&format!("/api/v1/files?limit=2&before={cursor}"), &alice)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        page2.files.iter().map(|f| f.id).collect::<Vec<_>>(),
        vec![ids[0]]
    );
    assert!(page2.next_cursor.is_none());

    let bad = app.get_authed("/api/v1/files?scope=everyone", &alice).await;
    assert_eq!(bad.status(), 422);
}
