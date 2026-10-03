//! HTTP handlers for uploads and files.

use axum::{extract::State, http::StatusCode};
use securedrop_common::{
    CreateUploadRequest, CreateUploadResponse, DownloadResponse, FileResponse,
};
use uuid::Uuid;

use super::service;
use crate::{
    auth::extractor::AuthUser,
    error::AppResult,
    extract::{ApiJson, ApiPath},
    middleware::client_meta::ClientMeta,
    state::AppState,
};

/// `POST /api/v1/uploads`
pub async fn create_upload(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiJson(req): ApiJson<CreateUploadRequest>,
) -> AppResult<(StatusCode, ApiJson<CreateUploadResponse>)> {
    let resp = service::create_upload(&state, user.user_id, req, &client).await?;
    Ok((StatusCode::CREATED, ApiJson(resp)))
}

/// `POST /api/v1/uploads/{id}/complete`
pub async fn complete_upload(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<ApiJson<FileResponse>> {
    Ok(ApiJson(
        service::complete_upload(&state, user.user_id, file_id, &client).await?,
    ))
}

/// `GET /api/v1/files/{id}`
pub async fn get_file(
    State(state): State<AppState>,
    user: AuthUser,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<ApiJson<FileResponse>> {
    Ok(ApiJson(
        service::get_file(&state, user.user_id, file_id).await?,
    ))
}

/// `GET /api/v1/files/{id}/download`
pub async fn download(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<ApiJson<DownloadResponse>> {
    Ok(ApiJson(
        service::download(&state, user.user_id, file_id, &client).await?,
    ))
}
