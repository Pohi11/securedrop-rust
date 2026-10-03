//! Rate limiting and HTTP hardening.
#![allow(clippy::unwrap_used)]

mod common;

use common::{TestApp, error_code};
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn auth_endpoints_are_rate_limited_per_ip(pool: PgPool) {
    let app = TestApp::spawn_with(pool, |c| {
        c.rate_limit.enabled = true;
        c.rate_limit.auth_per_minute = 6; // one every 10 s once the burst is spent
        c.rate_limit.auth_burst = 3;
    })
    .await;

    for _ in 0..3 {
        let resp = app.login("nobody@example.com", "whatever-password-1").await;
        assert_eq!(resp.status(), 401, "burst allowance");
    }
    let limited = app.login("nobody@example.com", "whatever-password-1").await;
    assert_eq!(limited.status(), 429);
    let retry_after: u64 = limited.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (1..=10).contains(&retry_after),
        "retry-after = {retry_after}"
    );
    assert_eq!(error_code(limited).await, "rate_limited");

    // Share-link redemption shares the strict per-IP policy (token guessing).
    let resp = app
        .client
        .post(app.url("/api/v1/shared/download"))
        .json(&json!({ "token": "guess" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn api_limit_is_per_user_not_per_ip(pool: PgPool) {
    let app = TestApp::spawn(pool.clone()).await;
    let alice = app.signup("alice@example.com").await.access_token;
    let bob = app.signup("bob@example.com").await.access_token;
    drop(app);

    // Same database, now with a tiny API budget (and auth limits out of the way).
    let app = TestApp::spawn_with(pool, |c| {
        c.rate_limit.enabled = true;
        c.rate_limit.api_per_minute = 2;
        c.rate_limit.api_burst = 2;
    })
    .await;

    assert_eq!(app.get_authed("/api/v1/me", &alice).await.status(), 200);
    assert_eq!(app.get_authed("/api/v1/me", &alice).await.status(), 200);
    assert_eq!(app.get_authed("/api/v1/me", &alice).await.status(), 429);
    // Bob comes from the same IP but has his own budget.
    assert_eq!(app.get_authed("/api/v1/me", &bob).await.status(), 200);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn security_headers_on_every_response(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    for path in ["/healthz", "/api/v1/me", "/no/such/route"] {
        let resp = app.client.get(app.url(path)).send().await.unwrap();
        let h = resp.headers();
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["cache-control"], "no-store", "{path}");
        assert_eq!(h["x-frame-options"], "DENY", "{path}");
        assert_eq!(h["referrer-policy"], "no-referrer", "{path}");
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("default-src 'none'")
        );
        assert!(h.contains_key("strict-transport-security"));
    }
    let missing = app
        .client
        .get(app.url("/no/such/route"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(error_code(missing).await, "not_found");
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn cors_only_allows_configured_origins(pool: PgPool) {
    let app = TestApp::spawn_with(pool, |c| {
        c.http.cors_allowed_origins = vec!["https://app.example.com".into()]
    })
    .await;

    let preflight = |origin: &'static str| {
        app.client
            .request(reqwest::Method::OPTIONS, app.url("/api/v1/me"))
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "authorization")
            .send()
    };
    let good = preflight("https://app.example.com").await.unwrap();
    assert_eq!(
        good.headers()["access-control-allow-origin"],
        "https://app.example.com"
    );
    assert!(
        !good
            .headers()
            .contains_key("access-control-allow-credentials")
    );

    let evil = preflight("https://evil.example.net").await.unwrap();
    assert!(!evil.headers().contains_key("access-control-allow-origin"));
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn oversized_bodies_are_rejected(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let huge = "x".repeat(200 * 1024);
    let resp = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": "a@example.com", "password": huge }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    assert_eq!(error_code(resp).await, "payload_too_large");
}
