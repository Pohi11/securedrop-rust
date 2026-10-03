//! HTTP handlers for uploads and files.

use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use securedrop_common::{
    CreateUploadRequest, CreateUploadResponse, DownloadResponse, FileListResponse, FileResponse,
    PresignPartsRequest, PresignPartsResponse, UploadProgressResponse,
};
use serde::Deserialize;
use uuid::Uuid;

use super::service;
use crate::{
    auth::extractor::AuthUser,
    error::{AppError, AppResult},
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

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// `owned` (default) or `shared` (files other users granted you).
    #[serde(default)]
    pub scope: Option<String>,
    pub before: Option<Uuid>,
    pub limit: Option<i64>,
}

/// `GET /api/v1/files?scope=owned|shared&before=<id>&limit=<n>`
pub async fn list_files(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> AppResult<ApiJson<FileListResponse>> {
    let shared = match q.scope.as_deref() {
        None | Some("owned") => false,
        Some("shared") => true,
        Some(_) => return Err(AppError::validation("scope must be 'owned' or 'shared'")),
    };
    Ok(ApiJson(
        service::list_files(&state, user.user_id, shared, q.before, q.limit).await?,
    ))
}

/// `DELETE /api/v1/files/{id}`
pub async fn delete_file(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<StatusCode> {
    service::delete_file(&state, user.user_id, file_id, &client).await?;
    Ok(StatusCode::NO_CONTENT)
}
