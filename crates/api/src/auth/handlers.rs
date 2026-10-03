//! HTTP handlers for `/api/v1/auth/*`. Parse input, call the service, shape the response.

use axum::{extract::State, http::StatusCode};
use secrecy::SecretString;
use securedrop_common::{
    LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, UserResponse,
};

use super::{extractor::AuthUser, service};
use crate::{
    error::AppResult, extract::ApiJson, middleware::client_meta::ClientMeta, state::AppState,
};

pub async fn register(
    State(state): State<AppState>,
    client: ClientMeta,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> AppResult<(StatusCode, ApiJson<UserResponse>)> {
    let user = service::register(&state, req, &client).await?;
    Ok((StatusCode::CREATED, ApiJson(user)))
}

pub async fn login(
    State(state): State<AppState>,
    client: ClientMeta,
    ApiJson(req): ApiJson<LoginRequest>,
) -> AppResult<ApiJson<TokenResponse>> {
    let tokens = service::login(
        &state,
        &req.email,
        SecretString::from(req.password),
        &client,
    )
    .await?;
    Ok(ApiJson(tokens))
}

pub async fn refresh(
    State(state): State<AppState>,
    client: ClientMeta,
    ApiJson(req): ApiJson<RefreshRequest>,
) -> AppResult<ApiJson<TokenResponse>> {
    Ok(ApiJson(
        service::refresh(&state, &req.refresh_token, &client).await?,
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
) -> AppResult<StatusCode> {
    service::logout(&state, user.user_id, user.session_id, &client).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn logout_all(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
) -> AppResult<StatusCode> {
    service::logout_all(&state, user.user_id, user.session_id, &client).await?;
    Ok(StatusCode::NO_CONTENT)
}
