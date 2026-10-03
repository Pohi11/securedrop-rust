//! Shared integration-test harness.
//!
//! Each test gets:
//! * a brand-new PostgreSQL database (created and migrated by `#[sqlx::test]`),
//! * a unique Redis key prefix (so tests never see each other's rate limits or denylists),
//! * the real router served over real HTTP on an ephemeral port.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use securedrop_api::{config::Config, state::AppState};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

pub struct TestApp {
    pub base_url: String,
    pub client: reqwest::Client,
    pub state: AppState,
}

pub fn test_config() -> Config {
    let mut config = Config::from_env().expect("load config from env/.env");
    config.redis.key_prefix = format!("test:{}:", Uuid::new_v4());
    config.http.bind_addr = "127.0.0.1:0".parse().unwrap();
    config
}

impl TestApp {
    pub async fn spawn(pool: PgPool) -> Self {
        Self::spawn_with(pool, |_| {}).await
    }

    pub async fn spawn_with(pool: PgPool, customize: impl FnOnce(&mut Config)) -> Self {
        let mut config = test_config();
        customize(&mut config);

        let (router, state) = securedrop_api::build_app_with_pool(config, pool)
            .await
            .expect("build app");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        Self {
            base_url: format!("http://{addr}"),
            client: reqwest::Client::new(),
            state,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

pub const PASSWORD: &str = "violet-tractor-mango-91";

impl TestApp {
    pub async fn register(&self, email: &str, password: &str) -> reqwest::Response {
        self.client
            .post(self.url("/api/v1/auth/register"))
            .json(&serde_json::json!({ "email": email, "password": password }))
            .send()
            .await
            .unwrap()
    }

    pub async fn login(&self, email: &str, password: &str) -> reqwest::Response {
        self.client
            .post(self.url("/api/v1/auth/login"))
            .json(&serde_json::json!({ "email": email, "password": password }))
            .send()
            .await
            .unwrap()
    }

    /// Register + login, returning the token pair.
    pub async fn signup(&self, email: &str) -> securedrop_common::TokenResponse {
        assert_eq!(self.register(email, PASSWORD).await.status(), 201);
        let resp = self.login(email, PASSWORD).await;
        assert_eq!(resp.status(), 200);
        resp.json().await.unwrap()
    }

    pub async fn refresh(&self, refresh_token: &str) -> reqwest::Response {
        self.client
            .post(self.url("/api/v1/auth/refresh"))
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .send()
            .await
            .unwrap()
    }

    pub async fn get_authed(&self, path: &str, token: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }

    pub async fn post_authed(
        &self,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap()
    }
}

pub async fn error_code(resp: reqwest::Response) -> String {
    let body: serde_json::Value = resp.json().await.unwrap();
    body["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}
