//! Wire types shared by the SecureDrop API server and its clients.
//!
//! Keeping request/response shapes in one crate means the CLI and the server cannot drift
//! apart silently: a breaking change to a field fails to compile on both sides.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Every non-2xx response has this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// Stable, machine-readable error code (e.g. `invalid_credentials`).
    pub code: String,
    /// Human-readable message. Never contains internal details.
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

// ---------------------------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
}

// Hand-written so tokens never end up in logs via `{:?}`.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &"[REDACTED]")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub storage_quota_bytes: u64,
    pub storage_used_bytes: u64,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------------------------
// Files & transfers
// ---------------------------------------------------------------------------------------------

/// A request the client must perform itself, directly against S3: method + URL + the exact
/// headers that were signed. Changing any signed header invalidates the signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct PresignedRequest {
    pub method: String,
    pub url: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub expires_at: DateTime<Utc>,
}

// Presigned URLs are bearer credentials: keep them out of Debug output and logs.
impl std::fmt::Debug for PresignedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignedRequest")
            .field("method", &self.method)
            .field("url", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUploadRequest {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 of the entire file, computed by the client before uploading.
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUploadResponse {
    pub file_id: Uuid,
    pub upload: UploadInstructions,
    pub upload_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UploadInstructions {
    /// PUT the whole file with this presigned request.
    Single { request: PresignedRequest },
    /// Split the file into `part_count` parts of `part_size` bytes (last part may be smaller),
    /// then request presigned URLs for the parts.
    Multipart { part_size: u64, part_count: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Pending,
    Available,
    Failed,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResponse {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 of the file.
    pub sha256: String,
    pub status: FileStatus,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResponse {
    pub file_id: Uuid,
    pub filename: String,
    pub size_bytes: u64,
    /// Verify the downloaded bytes against this.
    pub sha256: String,
    pub request: PresignedRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartChecksum {
    pub part_number: u32,
    /// Hex-encoded SHA-256 of this part's bytes.
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignPartsRequest {
    pub parts: Vec<PartChecksum>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedPart {
    pub part_number: u32,
    pub size_bytes: u64,
    pub request: PresignedRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignPartsResponse {
    pub parts: Vec<PresignedPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadedPartInfo {
    pub part_number: u32,
    pub size_bytes: u64,
}

/// Where a multipart upload stands, so an interrupted client can resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadProgressResponse {
    pub file_id: Uuid,
    pub status: FileStatus,
    pub part_size: u64,
    pub part_count: u32,
    pub uploaded_parts: Vec<UploadedPartInfo>,
    pub missing_parts: Vec<u32>,
    pub upload_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileListResponse {
    pub files: Vec<FileResponse>,
    /// Pass as `?before=` to fetch the next page. `None` when there are no more results.
    pub next_cursor: Option<Uuid>,
}

// ---------------------------------------------------------------------------------------------
// Sharing
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGrantRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantResponse {
    pub user_id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateShareLinkRequest {
    /// Lifetime of the link in seconds (default 24h, max 7 days).
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
    /// Maximum number of downloads (unlimited until expiry if omitted).
    #[serde(default)]
    pub max_downloads: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLinkResponse {
    pub id: Uuid,
    pub file_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub max_downloads: Option<u32>,
    pub download_count: u32,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// Returned once, at creation. The token is never retrievable again (only its hash is stored).
#[derive(Clone, Serialize, Deserialize)]
pub struct CreatedShareLinkResponse {
    pub link: ShareLinkResponse,
    pub token: String,
}

impl std::fmt::Debug for CreatedShareLinkResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedShareLinkResponse")
            .field("link", &self.link)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Redeeming a share link. The token travels in the body, not the URL, so it does not end up
/// in access logs, proxy logs or browser history.
#[derive(Clone, Serialize, Deserialize)]
pub struct RedeemShareRequest {
    pub token: String,
}
