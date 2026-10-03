//! Request extractors with consistent JSON error responses.

use axum::{
    extract::{FromRequest, rejection::JsonRejection},
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
