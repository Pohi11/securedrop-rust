//! Request ids, readiness and metrics.
#![allow(clippy::unwrap_used)]

mod common;

use common::{PASSWORD, TestApp};
use sqlx::PgPool;

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn every_response_carries_a_request_id_that_reaches_the_audit_log(pool: PgPool) {
    let app = TestApp::spawn(pool.clone()).await;

    // Generated when absent.
    let resp = app.client.get(app.url("/healthz")).send().await.unwrap();
    let generated = resp.headers()["x-request-id"].to_str().unwrap().to_string();
    assert_eq!(generated.len(), 36, "uuid");

    // Kept when a sane one is supplied (e.g. by the load balancer or a calling service).
    let resp = app
        .client
        .get(app.url("/healthz"))
        .header("x-request-id", "trace-abc_123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["x-request-id"], "trace-abc_123");

    // Replaced when it isn't (log-injection attempt).
    let resp = app
        .client
        .get(app.url("/healthz"))
        .header("x-request-id", "x".repeat(200))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.headers()["x-request-id"], "x".repeat(200).as_str());

    // The id a user would quote in a bug report finds the audit row.
    app.register("alice@example.com", PASSWORD).await;
    let resp = app.login("alice@example.com", PASSWORD).await;
    let request_id = resp.headers()["x-request-id"].to_str().unwrap().to_string();
    let action: String =
        sqlx::query_scalar("SELECT action FROM audit_events WHERE request_id = $1")
            .bind(&request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(action, "auth.login");
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn readiness_checks_all_dependencies(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let resp = app.client.get(app.url("/readyz")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ready");
    for dep in ["database", "redis", "storage"] {
        assert_eq!(body["checks"][dep], "ok", "{dep}");
    }
}

#[sqlx::test(migrator = "securedrop_api::database::MIGRATOR")]
async fn http_metrics_use_route_templates(pool: PgPool) {
    let app = TestApp::spawn(pool).await;
    let token = app.signup("bob@example.com").await.access_token;
    let id = uuid::Uuid::now_v7();
    app.get_authed(&format!("/api/v1/files/{id}"), &token).await;

    let handle = securedrop_api::telemetry::metrics::init().unwrap();
    let rendered = handle.render();
    assert!(rendered.contains("http_requests_total"), "{rendered}");
    assert!(
        rendered.contains(r#"route="/api/v1/files/{id}""#),
        "templated route label"
    );
    assert!(
        !rendered.contains(&id.to_string()),
        "raw ids must never become labels"
    );
    assert!(rendered.contains("http_request_duration_seconds_bucket"));
}
