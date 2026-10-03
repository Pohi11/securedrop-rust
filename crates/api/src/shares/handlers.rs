//! HTTP handlers for grants and share links.

use axum::{extract::State, http::StatusCode};
use securedrop_common::{
    CreateGrantRequest, CreateShareLinkRequest, CreatedShareLinkResponse, DownloadResponse,
    GrantResponse, RedeemShareRequest, ShareLinkResponse,
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

/// `POST /api/v1/files/{id}/grants`
pub async fn create_grant(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath(file_id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<CreateGrantRequest>,
) -> AppResult<(StatusCode, ApiJson<GrantResponse>)> {
    let grant = service::grant(&state, user.user_id, file_id, &req.email, &client).await?;
    Ok((StatusCode::CREATED, ApiJson(grant)))
}

/// `GET /api/v1/files/{id}/grants`
pub async fn list_grants(
    State(state): State<AppState>,
    user: AuthUser,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<ApiJson<Vec<GrantResponse>>> {
    Ok(ApiJson(
        service::list_grants(&state, user.user_id, file_id).await?,
    ))
}

/// `DELETE /api/v1/files/{id}/grants/{user_id}`
pub async fn revoke_grant(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath((file_id, grantee_id)): ApiPath<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    service::revoke_grant(&state, user.user_id, file_id, grantee_id, &client).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/files/{id}/share-links`
pub async fn create_link(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath(file_id): ApiPath<Uuid>,
    ApiJson(req): ApiJson<CreateShareLinkRequest>,
) -> AppResult<(StatusCode, ApiJson<CreatedShareLinkResponse>)> {
    let link = service::create_link(&state, user.user_id, file_id, req, &client).await?;
    Ok((StatusCode::CREATED, ApiJson(link)))
}

/// `GET /api/v1/files/{id}/share-links`
pub async fn list_links(
    State(state): State<AppState>,
    user: AuthUser,
    ApiPath(file_id): ApiPath<Uuid>,
) -> AppResult<ApiJson<Vec<ShareLinkResponse>>> {
    Ok(ApiJson(
        service::list_links(&state, user.user_id, file_id).await?,
    ))
}

/// `DELETE /api/v1/files/{id}/share-links/{link_id}`
pub async fn revoke_link(
    State(state): State<AppState>,
    user: AuthUser,
    client: ClientMeta,
    ApiPath((file_id, link_id)): ApiPath<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    service::revoke_link(&state, user.user_id, file_id, link_id, &client).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/shared/download`: public (no auth); the share token is the credential.
pub async fn redeem(
    State(state): State<AppState>,
    client: ClientMeta,
    ApiJson(req): ApiJson<RedeemShareRequest>,
) -> AppResult<ApiJson<DownloadResponse>> {
    Ok(ApiJson(service::redeem(&state, &req.token, &client).await?))
}
