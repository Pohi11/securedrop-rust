//! `AuthUser`: an Axum extractor that authenticates the request.
//!
//! Adding `user: AuthUser` to a handler's arguments is all it takes to require authentication.
//! There is no way to forget a check: the handler cannot even be called without one.

use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub token_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        // Cache per request, in case several extractors/middleware need the user.
        if let Some(user) = parts.extensions.get::<AuthUser>() {
            return Ok(*user);
        }

        let token = bearer_token(parts).ok_or(AppError::Unauthorized)?;
        let claims = state.jwt.verify(token)?;

        if state.revocations.is_revoked(claims.sid).await? {
            return Err(AppError::Unauthorized);
        }

        let user = AuthUser {
            user_id: claims.sub,
            session_id: claims.sid,
            token_id: claims.jti,
        };
        parts.extensions.insert(user);
        Ok(user)
    }
}

/// Extract the token from `Authorization: Bearer <token>` (scheme is case-insensitive per RFC 7235).
fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}
