//! Wire types shared by the SecureDrop API server and its clients.
//!
//! Keeping request/response shapes in one crate means the CLI and the server cannot drift
//! apart silently: a breaking change to a field fails to compile on both sides.

use serde::{Deserialize, Serialize};

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
