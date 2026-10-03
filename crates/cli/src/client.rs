//! Typed HTTP client for the SecureDrop API.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use reqwest::{Method, StatusCode};
use securedrop_common::{
    CreateShareLinkRequest, CreateUploadRequest, CreateUploadResponse, CreatedShareLinkResponse,
    DownloadResponse, ErrorBody, FileListResponse, FileResponse, GrantResponse, PartChecksum,
    PresignPartsResponse, TokenResponse, UploadProgressResponse, UserResponse,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::credentials::{CredentialStore, Credentials};

/// An error response from the API, with its stable machine-readable code.
#[derive(Debug, thiserror::Error)]
#[error("{message} ({code}, HTTP {status})")]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    creds: Arc<Mutex<Option<Credentials>>>,
    store: Option<CredentialStore>,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("securedrop-cli/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            creds: Arc::new(Mutex::new(None)),
            store: None,
        })
    }

    /// Load saved credentials from (and persist refreshed ones to) `store`.
    pub fn with_store(mut self, store: CredentialStore) -> anyhow::Result<Self> {
        if let Some(saved) = store.load()? {
            self.creds = Arc::new(Mutex::new(Some(saved)));
        }
        self.store = Some(store);
        Ok(self)
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // --- auth --------------------------------------------------------------------------------

    pub async fn register(&self, email: &str, password: &str) -> anyhow::Result<UserResponse> {
        self.request(
            Method::POST,
            "/api/v1/auth/register",
            Some(&json!({ "email": email, "password": password })),
            false,
        )
        .await
    }

    pub async fn login(&self, email: &str, password: &str) -> anyhow::Result<()> {
        let tokens: TokenResponse = self
            .request(
                Method::POST,
                "/api/v1/auth/login",
                Some(&json!({ "email": email, "password": password })),
                false,
            )
            .await?;
        self.save_tokens(tokens).await
    }

    pub async fn logout(&self) -> anyhow::Result<()> {
        let result: anyhow::Result<serde_json::Value> = self
            .request(Method::POST, "/api/v1/auth/logout", Some(&json!({})), true)
            .await;
        // Forget local credentials even if the server call failed (e.g. already expired).
        *self.creds.lock().await = None;
        if let Some(store) = &self.store {
            store.clear()?;
        }
        result.map(|_| ())
    }

    pub async fn me(&self) -> anyhow::Result<UserResponse> {
        self.request::<(), _>(Method::GET, "/api/v1/me", None, true)
            .await
    }

    // --- uploads -----------------------------------------------------------------------------

    pub async fn create_upload(
        &self,
        req: &CreateUploadRequest,
    ) -> anyhow::Result<CreateUploadResponse> {
        self.request(Method::POST, "/api/v1/uploads", Some(req), true)
            .await
    }

    pub async fn presign_parts(
        &self,
        file_id: Uuid,
        parts: Vec<PartChecksum>,
    ) -> anyhow::Result<PresignPartsResponse> {
        self.request(
            Method::POST,
            &format!("/api/v1/uploads/{file_id}/parts"),
            Some(&json!({ "parts": parts })),
            true,
        )
        .await
    }

    pub async fn upload_progress(&self, file_id: Uuid) -> anyhow::Result<UploadProgressResponse> {
        self.request::<(), _>(
            Method::GET,
            &format!("/api/v1/uploads/{file_id}/parts"),
            None,
            true,
        )
        .await
    }

    pub async fn complete_upload(&self, file_id: Uuid) -> anyhow::Result<FileResponse> {
        self.request(
            Method::POST,
            &format!("/api/v1/uploads/{file_id}/complete"),
            Some(&json!({})),
            true,
        )
        .await
    }

    pub async fn abort_upload(&self, file_id: Uuid) -> anyhow::Result<()> {
        self.request::<(), serde_json::Value>(
            Method::DELETE,
            &format!("/api/v1/uploads/{file_id}"),
            None,
            true,
        )
        .await
        .map(|_| ())
    }

    // --- files -------------------------------------------------------------------------------

    pub async fn list_files(
        &self,
        shared: bool,
        before: Option<Uuid>,
    ) -> anyhow::Result<FileListResponse> {
        let mut path = format!(
            "/api/v1/files?scope={}",
            if shared { "shared" } else { "owned" }
        );
        if let Some(before) = before {
            path.push_str(&format!("&before={before}"));
        }
        self.request::<(), _>(Method::GET, &path, None, true).await
    }

    pub async fn delete_file(&self, file_id: Uuid) -> anyhow::Result<()> {
        self.request::<(), serde_json::Value>(
            Method::DELETE,
            &format!("/api/v1/files/{file_id}"),
            None,
            true,
        )
        .await
        .map(|_| ())
    }

    pub async fn download_info(&self, file_id: Uuid) -> anyhow::Result<DownloadResponse> {
        self.request::<(), _>(
            Method::GET,
            &format!("/api/v1/files/{file_id}/download"),
            None,
            true,
        )
        .await
    }

    // --- sharing -----------------------------------------------------------------------------

    pub async fn grant(&self, file_id: Uuid, email: &str) -> anyhow::Result<GrantResponse> {
        self.request(
            Method::POST,
            &format!("/api/v1/files/{file_id}/grants"),
            Some(&json!({ "email": email })),
            true,
        )
        .await
    }

    pub async fn create_share_link(
        &self,
        file_id: Uuid,
        req: &CreateShareLinkRequest,
    ) -> anyhow::Result<CreatedShareLinkResponse> {
        self.request(
            Method::POST,
            &format!("/api/v1/files/{file_id}/share-links"),
            Some(req),
            true,
        )
        .await
    }

    pub async fn revoke_share_link(&self, file_id: Uuid, link_id: Uuid) -> anyhow::Result<()> {
        self.request::<(), serde_json::Value>(
            Method::DELETE,
            &format!("/api/v1/files/{file_id}/share-links/{link_id}"),
            None,
            true,
        )
        .await
        .map(|_| ())
    }

    /// Redeem a share link (no login needed).
    pub async fn redeem_share(&self, token: &str) -> anyhow::Result<DownloadResponse> {
        self.request(
            Method::POST,
            "/api/v1/shared/download",
            Some(&json!({ "token": token })),
            false,
        )
        .await
    }

    // --- plumbing ----------------------------------------------------------------------------

    /// Send a request; on 401 refresh the access token once and retry; on 429 honour
    /// `Retry-After` once (capped) and retry.
    async fn request<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        auth: bool,
    ) -> anyhow::Result<T> {
        let mut refreshed = false;
        let mut throttled = false;
        loop {
            let mut req = self
                .http
                .request(method.clone(), format!("{}{path}", self.base_url));
            if auth {
                let creds = self.creds.lock().await;
                let creds = creds
                    .as_ref()
                    .context("not logged in (run `securedrop login`)")?;
                req = req.bearer_auth(&creds.access_token);
            }
            if let Some(body) = body {
                req = req.json(body);
            }
            let resp = req
                .send()
                .await
                .with_context(|| format!("request to {path} failed"))?;
            let status = resp.status();

            if status == StatusCode::UNAUTHORIZED && auth && !refreshed {
                refreshed = true;
                if self.refresh().await.is_ok() {
                    continue;
                }
            }
            if status == StatusCode::TOO_MANY_REQUESTS && !throttled {
                throttled = true;
                let wait = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1)
                    .min(30);
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
            if !status.is_success() {
                return Err(api_error(resp).await.into());
            }
            if status == StatusCode::NO_CONTENT {
                return serde_json::from_value(serde_json::Value::Null)
                    .context("unexpected empty response");
            }
            return resp.json().await.context("invalid JSON from server");
        }
    }

    async fn refresh(&self) -> anyhow::Result<()> {
        let refresh_token = {
            let creds = self.creds.lock().await;
            creds
                .as_ref()
                .context("not logged in")?
                .refresh_token
                .clone()
        };
        let resp = self
            .http
            .post(format!("{}/api/v1/auth/refresh", self.base_url))
            .json(&json!({ "refresh_token": refresh_token }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(api_error(resp).await.into());
        }
        let tokens: TokenResponse = resp.json().await?;
        self.save_tokens(tokens).await
    }

    async fn save_tokens(&self, tokens: TokenResponse) -> anyhow::Result<()> {
        let creds = Credentials {
            api_url: self.base_url.clone(),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        };
        if let Some(store) = &self.store {
            store.save(&creds)?;
        }
        *self.creds.lock().await = Some(creds);
        Ok(())
    }
}

async fn api_error(resp: reqwest::Response) -> ApiError {
    let status = resp.status();
    match resp.json::<ErrorBody>().await {
        Ok(body) => ApiError {
            status,
            code: body.error.code,
            message: body.error.message,
        },
        Err(_) => ApiError {
            status,
            code: "unknown".into(),
            message: status.canonical_reason().unwrap_or("request failed").into(),
        },
    }
}
