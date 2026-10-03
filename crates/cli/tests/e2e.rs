//! The CLI library end to end against a real API + Postgres + Redis + S3 store.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use securedrop_cli::{
    ApiClient, ApiError, CredentialStore,
    credentials::Credentials,
    transfer::{self, UploadOptions, UploadOutcome},
};
use securedrop_common::CreateShareLinkRequest;
use sqlx::PgPool;
use tokio::net::TcpListener;

const MIB: u64 = 1024 * 1024;
const PASSWORD: &str = "violet-tractor-mango-91";

async fn spawn_api(pool: PgPool) -> String {
    let mut config = securedrop_api::config::Config::from_env().unwrap();
    config.redis.key_prefix = format!("test:{}:", uuid::Uuid::new_v4());
    config.rate_limit.enabled = false;
    config.uploads.single_part_max = 5 * MIB;
    config.uploads.part_size = 5 * MIB;
    let (router, _state) = securedrop_api::build_app_with_pool(config, pool)
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum_serve(listener, router).await;
    });
    format!("http://{addr}")
}

async fn axum_serve(listener: TcpListener, router: axum::Router) {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

fn test_bytes(len: u64) -> Vec<u8> {
    let mut data = b"SecureDrop CLI e2e\n".to_vec();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    while (data.len() as u64) < len {
        x ^= x << 7;
        x ^= x >> 9;
        data.push((x & 0xff) as u8);
    }
    data
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn interrupted_upload_resumes_then_downloads_verified(pool: PgPool) {
    let api = spawn_api(pool).await;
    let home = tempfile::tempdir().unwrap();
    let store = CredentialStore::new(home.path());
    let client = ApiClient::new(&api)
        .unwrap()
        .with_store(store.clone())
        .unwrap();

    client.register("cli@example.com", PASSWORD).await.unwrap();
    client.login("cli@example.com", PASSWORD).await.unwrap();
    assert!(store.load().unwrap().is_some(), "tokens persisted");

    // 13 MiB -> 3 parts of 5/5/3 MiB.
    let data = test_bytes(13 * MIB);
    let src = home.path().join("dataset.bin");
    std::fs::write(&src, &data).unwrap();

    let mut opts = UploadOptions {
        content_type: None,
        concurrency: 2,
        state_dir: home.path().to_path_buf(),
        stop_after_parts: Some(1),
        progress: false,
    };
    let first = transfer::upload(&client, &src, &opts).await.unwrap();
    let UploadOutcome::Interrupted {
        file_id,
        parts_remaining,
    } = first
    else {
        panic!("expected an interrupted upload, got {first:?}");
    };
    assert_eq!(parts_remaining, 2);

    // A fresh client (as after a restart) resumes from the saved state.
    let client = ApiClient::new(&api)
        .unwrap()
        .with_store(store.clone())
        .unwrap();
    opts.stop_after_parts = None;
    let UploadOutcome::Completed(file) = transfer::upload(&client, &src, &opts).await.unwrap()
    else {
        panic!("expected completion");
    };
    assert_eq!(
        file.id, file_id,
        "resumed the same upload instead of starting over"
    );
    assert_eq!(file.size_bytes, data.len() as u64);

    let info = client.download_info(file.id).await.unwrap();
    let dest = home.path().join("restored.bin");
    transfer::download_to(&client, &info, &dest, false, false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    // Refuses to clobber existing files without --force.
    assert!(
        transfer::download_to(&client, &info, &dest, false, false)
            .await
            .is_err()
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn tampered_downloads_never_reach_the_destination(pool: PgPool) {
    let api = spawn_api(pool).await;
    let home = tempfile::tempdir().unwrap();
    let client = ApiClient::new(&api).unwrap();
    client.register("t@example.com", PASSWORD).await.unwrap();
    client.login("t@example.com", PASSWORD).await.unwrap();

    let src = home.path().join("note.txt");
    std::fs::write(&src, b"integrity matters").unwrap();
    let opts = UploadOptions {
        content_type: None,
        concurrency: 1,
        state_dir: home.path().to_path_buf(),
        stop_after_parts: None,
        progress: false,
    };
    let UploadOutcome::Completed(file) = transfer::upload(&client, &src, &opts).await.unwrap()
    else {
        panic!()
    };

    let mut info = client.download_info(file.id).await.unwrap();
    info.sha256 = "00".repeat(32); // pretend the bytes were swapped in transit
    let dest = home.path().join("out.txt");
    let err = transfer::download_to(&client, &info, &dest, false, false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("integrity check failed"), "{err}");
    assert!(!dest.exists());
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn share_links_and_token_refresh(pool: PgPool) {
    let api = spawn_api(pool).await;
    let home = tempfile::tempdir().unwrap();
    let store = CredentialStore::new(home.path());
    let owner = ApiClient::new(&api)
        .unwrap()
        .with_store(store.clone())
        .unwrap();
    owner.register("owner@example.com", PASSWORD).await.unwrap();
    owner.login("owner@example.com", PASSWORD).await.unwrap();

    let src = home.path().join("hello.txt");
    std::fs::write(&src, b"hello from a share link").unwrap();
    let opts = UploadOptions {
        content_type: None,
        concurrency: 1,
        state_dir: home.path().to_path_buf(),
        stop_after_parts: None,
        progress: false,
    };
    let UploadOutcome::Completed(file) = transfer::upload(&owner, &src, &opts).await.unwrap()
    else {
        panic!()
    };
    let link = owner
        .create_share_link(
            file.id,
            &CreateShareLinkRequest {
                expires_in_secs: Some(600),
                max_downloads: Some(1),
            },
        )
        .await
        .unwrap();

    // Someone with no account redeems it.
    let anonymous = ApiClient::new(&api).unwrap();
    let info = anonymous.redeem_share(&link.token).await.unwrap();
    let dest = home.path().join("received.txt");
    transfer::download_to(&anonymous, &info, &dest, false, false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"hello from a share link");

    let err = anonymous.redeem_share(&link.token).await.unwrap_err();
    let api_err = err.downcast_ref::<ApiError>().expect("typed API error");
    assert_eq!(api_err.code, "not_found", "single-use link is exhausted");

    // Expired/garbage access token: the client refreshes transparently and saves new tokens.
    let saved = store.load().unwrap().unwrap();
    store
        .save(&Credentials {
            access_token: "garbage".into(),
            ..saved.clone()
        })
        .unwrap();
    let reloaded = ApiClient::new(&api)
        .unwrap()
        .with_store(store.clone())
        .unwrap();
    assert_eq!(reloaded.me().await.unwrap().email, "owner@example.com");
    let after = store.load().unwrap().unwrap();
    assert_ne!(
        after.refresh_token, saved.refresh_token,
        "rotated refresh token was persisted"
    );

    reloaded.logout().await.unwrap();
    assert!(store.load().unwrap().is_none());
}
