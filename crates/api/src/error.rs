//! The single error type returned by handlers.
//!
//! Design rules:
//! * Every variant maps to exactly one HTTP status and a stable machine-readable `code`.
//! * Client-facing messages never include internal details (SQL, S3, stack traces).
//!   Internal errors are logged with full context and the client gets a generic message.
//! * Authorization failures on resources the caller cannot see are reported as `NotFound`
//!   (see `files::authz`) so the API does not act as an existence oracle.

use std::time::Duration;

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use securedrop_common::{ErrorBody, ErrorDetail};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("authentication required")]
    Unauthorized,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("forbidden")]
    Forbidden,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("storage quota exceeded")]
    QuotaExceeded,

    #[error("upload verification failed: {0}")]
    IntegrityCheckFailed(String),

    #[error("rate limit exceeded")]
    RateLimited { retry_after: Duration },

    #[error("service temporarily unavailable")]
    Unavailable,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    pub fn internal(err: impl Into<anyhow::Error>) -> Self {
        Self::Internal(err.into())
    }

    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::QuotaExceeded => (StatusCode::INSUFFICIENT_STORAGE, "quota_exceeded"),
            Self::IntegrityCheckFailed(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "integrity_check_failed")
            }
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }

    /// The message safe to show to API clients.
    fn public_message(&self) -> String {
        match self {
            // Internal details stay in the logs.
            Self::Internal(_) => "an internal error occurred".to_string(),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();

        match &self {
            // `{:#}` prints the whole anyhow context chain.
            Self::Internal(err) => tracing::error!(error = format!("{err:#}"), "internal error"),
            Self::Unavailable => tracing::warn!("dependency unavailable"),
            _ => tracing::debug!(%status, code, "request rejected"),
        }

        let body = ErrorBody {
            error: ErrorDetail {
                code: code.to_string(),
                message: self.public_message(),
            },
        };
        let mut response = (status, Json(body)).into_response();

        if let Self::RateLimited { retry_after } = self {
            let secs = retry_after.as_secs().max(1);
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(anyhow::Error::new(err).context("database error"))
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        Self::Internal(anyhow::Error::new(err).context("redis error"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_details() {
        let err = AppError::Internal(anyhow::anyhow!("password=hunter2 at db.internal:5432"));
        assert_eq!(err.public_message(), "an internal error occurred");
        assert_eq!(err.status_and_code().0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn rate_limited_sets_retry_after() {
        let resp = AppError::RateLimited {
            retry_after: Duration::from_millis(2500),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "2");
    }
}
