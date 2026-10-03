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
