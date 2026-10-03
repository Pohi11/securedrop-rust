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
    // Most tests make many auth calls from 127.0.0.1; rate-limit tests opt back in.
    config.rate_limit.enabled = false;
    config.http.bind_addr = "127.0.0.1:0".parse().unwrap();
    config
}

impl TestApp {
    pub async fn spawn(pool: PgPool) -> Self {
        Self::spawn_with(pool, |_| {}).await
    }

    pub async fn spawn_with(pool: PgPool, customize: impl FnOnce(&mut Config)) -> Self {
        // Logs show up for failing tests (captured otherwise). Control with RUST_LOG.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "warn,securedrop_api=info".into()),
            )
            .with_test_writer()
            .try_init();
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

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Execute a presigned request exactly as a client would: same method, URL and signed headers.
pub async fn execute_presigned(
    client: &reqwest::Client,
    req: &securedrop_common::PresignedRequest,
    body: Option<Vec<u8>>,
) -> reqwest::Response {
    let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap();
    let mut builder = client.request(method, &req.url);
    for (name, value) in &req.headers {
        builder = builder.header(name, value);
    }
    if let Some(body) = body {
        builder = builder.body(body);
    }
    builder.send().await.unwrap()
}

impl TestApp {
    pub async fn create_upload(
        &self,
        token: &str,
        filename: &str,
        content_type: &str,
        data: &[u8],
    ) -> reqwest::Response {
        self.post_authed(
            "/api/v1/uploads",
            token,
            serde_json::json!({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": data.len(),
                "sha256": sha256_hex(data),
            }),
        )
        .await
    }

    pub async fn complete_upload(&self, token: &str, file_id: uuid::Uuid) -> reqwest::Response {
        self.post_authed(
            &format!("/api/v1/uploads/{file_id}/complete"),
            token,
            serde_json::json!({}),
        )
        .await
    }

    /// Full happy-path single-part upload. Returns the file id.
    pub async fn upload_file(
        &self,
        token: &str,
        filename: &str,
        content_type: &str,
        data: &[u8],
    ) -> uuid::Uuid {
        let resp = self
            .create_upload(token, filename, content_type, data)
            .await;
        assert_eq!(
            resp.status(),
            201,
            "create upload: {}",
            resp.text().await.unwrap()
        );
        let created: securedrop_common::CreateUploadResponse = resp.json().await.unwrap();
        let securedrop_common::UploadInstructions::Single { request } = created.upload else {
            panic!("expected single-part upload");
        };
        let put = execute_presigned(&self.client, &request, Some(data.to_vec())).await;
        assert!(
            put.status().is_success(),
            "S3 PUT failed: {}",
            put.text().await.unwrap()
        );
        let done = self.complete_upload(token, created.file_id).await;
        assert_eq!(
            done.status(),
            200,
            "complete: {}",
            done.text().await.unwrap()
        );
        created.file_id
    }
}
