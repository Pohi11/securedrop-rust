//! Request extractors with consistent JSON error responses.

use axum::{
    extract::{
        FromRequest, FromRequestParts,
        rejection::{JsonRejection, PathRejection},
    },
    response::{IntoResponse, Response},
};

use crate::error::AppError;

/// Drop-in replacement for `axum::Json` whose rejections use our `{"error": {...}}` shape
/// instead of Axum's plain-text bodies.
#[derive(Debug, Clone, Copy, Default, FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct ApiJson<T>(pub T);

impl<T: serde::Serialize> IntoResponse for ApiJson<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        match rejection {
            // Valid JSON, wrong shape (missing field, wrong type): semantically invalid.
            JsonRejection::JsonDataError(e) => AppError::Validation(e.body_text()),
            // Unparseable body, missing Content-Type, unreadable body: syntactically invalid.
            other => AppError::BadRequest(other.body_text()),
        }
    }
}

/// Like `axum::extract::Path`, but a malformed id (e.g. not a UUID) yields our JSON 400.
#[derive(Debug, Clone, Copy, FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(AppError))]
pub struct ApiPath<T>(pub T);

impl From<PathRejection> for AppError {
    fn from(rejection: PathRejection) -> Self {
        AppError::BadRequest(rejection.body_text())
    }
}
