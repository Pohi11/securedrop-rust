use axum::{Json, extract::State};
use securedrop_common::UserResponse;

use super::repo;
use crate::{
    auth::extractor::AuthUser,
    error::{AppError, AppResult},
    state::AppState,
};

/// `GET /api/v1/me`
pub async fn me(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<UserResponse>> {
    let record = repo::find_by_id(&state.db, user.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let used = repo::storage_used(&state.db, user.user_id).await?;
    Ok(Json(UserResponse {
        id: record.id,
        email: record.email,
        storage_quota_bytes: u64::try_from(record.storage_quota_bytes).unwrap_or(0),
        storage_used_bytes: u64::try_from(used).unwrap_or(0),
        created_at: record.created_at,
    }))
}
