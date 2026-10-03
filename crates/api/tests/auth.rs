//! Authentication end to end over HTTP.
#![allow(clippy::unwrap_used)]

mod common;

use common::{PASSWORD, TestApp, error_code};
use securedrop_common::{TokenResponse, UserResponse};
use sqlx::PgPool;

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn register_login_and_me(pool: PgPool) {
    let app = TestApp::spawn(pool.clone()).await;

    let resp = app.register("  Alice@Example.com ", PASSWORD).await;
    assert_eq!(resp.status(), 201);
    let user: UserResponse = resp.json().await.unwrap();
    assert_eq!(user.email, "alice@example.com");

    // The stored hash is Argon2id, never the password.
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(stored.starts_with("$argon2id$"));
    assert!(!stored.contains(PASSWORD));

    let tokens: TokenResponse = app
        .login("alice@example.com", PASSWORD)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(tokens.token_type, "Bearer");

    let me: UserResponse = app
        .get_authed("/api/v1/me", &tokens.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me.id, user.id);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn registration_validation(pool: PgPool) {
    let app = TestApp::spawn(pool).await;

    let weak = app.register("bob@example.com", "password1234").await;
    assert_eq!(weak.status(), 422);
    assert_eq!(error_code(weak).await, "validation_error");

    assert_eq!(app.register("not-an-email", PASSWORD).await.status(), 422);

    assert_eq!(
        app.register("bob@example.com", PASSWORD).await.status(),
        201
    );
    // Same address with different case is the same account.
    assert_eq!(
        app.register("BOB@example.com", PASSWORD).await.status(),
        409
    );

    // Malformed JSON gets our JSON error shape, not Axum's plain text.
    let resp = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(error_code(resp).await, "bad_request");

    // Well-formed JSON with a missing field is a validation error.
    let resp = app
        .client
        .post(app.url("/api/v1/auth/register"))
        .json(&serde_json::json!({ "email": "x@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn wrong_password_and_unknown_user_are_indistinguishable(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    app.signup("carol@example.com").await;

    let wrong_pw = app
        .login("carol@example.com", "definitely-not-it-123")
        .await;
    let unknown = app
        .login("nobody@example.com", "definitely-not-it-123")
        .await;
    assert_eq!(wrong_pw.status(), 401);
    assert_eq!(unknown.status(), 401);
    assert_eq!(
        wrong_pw.text().await.unwrap(),
        unknown.text().await.unwrap(),
        "identical bodies, so the response doesn't reveal which accounts exist"
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn account_locks_after_repeated_failures(pool: PgPool) {
    let app = TestApp::spawn_with(pool.clone(), |c| c.auth.max_failed_logins = 3).await;
    app.signup("dave@example.com").await;

    for _ in 0..3 {
        assert_eq!(
            app.login("dave@example.com", "wrong-password-xyz")
                .await
                .status(),
            401
        );
    }
    // Even the correct password is refused while locked, with the same generic error.
    let locked = app.login("dave@example.com", PASSWORD).await;
    assert_eq!(locked.status(), 401);
    assert_eq!(error_code(locked).await, "invalid_credentials");

    let denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND outcome = 'denied'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(denied, 1);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn refresh_rotates_and_detects_reuse(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let first = app.signup("erin@example.com").await;

    // Normal rotation: old refresh token -> new pair.
    let resp = app.refresh(&first.refresh_token).await;
    assert_eq!(resp.status(), 200);
    let second: TokenResponse = resp.json().await.unwrap();
    assert_ne!(second.refresh_token, first.refresh_token);
    assert_eq!(
        second.refresh_expires_at, first.refresh_expires_at,
        "rotation must not extend the session"
    );
    assert_eq!(
        app.get_authed("/api/v1/me", &second.access_token)
            .await
            .status(),
        200
    );

    // An attacker replays the first (already used) refresh token.
    assert_eq!(app.refresh(&first.refresh_token).await.status(), 401);

    // The whole session is now dead: the legitimate latest refresh token...
    assert_eq!(app.refresh(&second.refresh_token).await.status(), 401);
    // ...and the access tokens already issued for the session.
    assert_eq!(
        app.get_authed("/api/v1/me", &second.access_token)
            .await
            .status(),
        401
    );
    assert_eq!(
        app.get_authed("/api/v1/me", &first.access_token)
            .await
            .status(),
        401
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn logout_revokes_session_but_not_other_sessions(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let laptop = app.signup("frank@example.com").await;
    let phone: TokenResponse = app
        .login("frank@example.com", PASSWORD)
        .await
        .json()
        .await
        .unwrap();

    let resp = app
        .post_authed(
            "/api/v1/auth/logout",
            &laptop.access_token,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 204);

    assert_eq!(
        app.get_authed("/api/v1/me", &laptop.access_token)
            .await
            .status(),
        401
    );
    assert_eq!(app.refresh(&laptop.refresh_token).await.status(), 401);
    assert_eq!(
        app.get_authed("/api/v1/me", &phone.access_token)
            .await
            .status(),
        200
    );
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn logout_all_revokes_every_session(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let laptop = app.signup("grace@example.com").await;
    let phone: TokenResponse = app
        .login("grace@example.com", PASSWORD)
        .await
        .json()
        .await
        .unwrap();

    let resp = app
        .post_authed(
            "/api/v1/auth/logout-all",
            &laptop.access_token,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 204);

    for t in [&laptop, &phone] {
        assert_eq!(
            app.get_authed("/api/v1/me", &t.access_token).await.status(),
            401
        );
        assert_eq!(app.refresh(&t.refresh_token).await.status(), 401);
    }
    // Logging in again works.
    assert_eq!(app.login("grace@example.com", PASSWORD).await.status(), 200);
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn rejects_missing_malformed_and_tampered_tokens(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let tokens = app.signup("heidi@example.com").await;

    let missing = app.client.get(app.url("/api/v1/me")).send().await.unwrap();
    assert_eq!(missing.status(), 401);
    assert_eq!(missing.headers()["www-authenticate"], "Bearer");

    let basic = app
        .client
        .get(app.url("/api/v1/me"))
        .header("authorization", "Basic YWxpY2U6cGFzcw==")
        .send()
        .await
        .unwrap();
    assert_eq!(basic.status(), 401);

    // Flip a character in the middle of the signature. (Not the last one: the final base64url
    // character carries unused padding bits, so changing it may not change the decoded bytes.)
    let mut tampered: Vec<char> = tokens.access_token.chars().collect();
    let i = tampered.len() - 10;
    tampered[i] = if tampered[i] == 'A' { 'B' } else { 'A' };
    let tampered: String = tampered.into_iter().collect();
    assert_eq!(app.get_authed("/api/v1/me", &tampered).await.status(), 401);

    // A refresh token is not an access token.
    assert_eq!(
        app.get_authed("/api/v1/me", &tokens.refresh_token)
            .await
            .status(),
        401
    );
}
