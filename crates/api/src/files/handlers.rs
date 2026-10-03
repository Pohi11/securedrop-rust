//! HTTP handlers for uploads and files.

use axum::{extract::State, http::StatusCode};
use securedrop_common::{
    CreateUploadRequest, CreateUploadResponse, DownloadResponse, FileResponse, PresignPartsRequest,
    PresignPartsResponse, UploadProgressResponse,
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

/// `POST /api/v1/uploads/{id}/parts`: presign URLs for specific parts.
pub async fn presign_parts(
    State(state): State<AppState>,
    user: AuthUser,
    ApiPath(file_id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<PresignPartsRequest>,
) -> AppResult<ApiJson<PresignPartsResponse>> {
    Ok(ApiJson(
        service::presign_parts(&state, user.user_id, file_id, req).await?,
    ))
}

/// `GET /api/v1/uploads/{id}/parts`: which parts S3 already has (for resuming).
pub async fn upload_progress(
    State(state): State<AppState>,
    user: AuthUser,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<ApiJson<UploadProgressResponse>> {
    Ok(ApiJson(
        service::upload_progress(&state, user.user_id, file_id).await?,
    ))
}

/// `DELETE /api/v1/uploads/{id}`: abort an in-progress upload.
pub async fn abort_upload(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<StatusCode> {
    service::abort_upload(&state, user.user_id, file_id, &client).await?;
    Ok(StatusCode::NO_CONTENT)
}
