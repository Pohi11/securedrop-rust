//! Sharing: direct grants to other users, and expiring bearer share links.

use std::time::Duration;

use chrono::{SubsecRound, Utc};
use securedrop_common::{
    CreateShareLinkRequest, CreatedShareLinkResponse, DownloadResponse, GrantResponse,
    ShareLinkResponse,
};
use serde_json::json;
use uuid::Uuid;

use super::repo::{self, ShareLinkRow};
use crate::{
    audit::{AuditEvent, Outcome},
    auth::tokens,
    error::{AppError, AppResult},
    files::{
        authz::{Action, load_authorized},
        model::STATUS_AVAILABLE,
        repo as files_repo,
    },
    middleware::client_meta::ClientMeta,
    state::AppState,
    storage::GetObjectSpec,
    users::{self, model::normalize_email},
};

const DEFAULT_LINK_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_LINK_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_LINK_DOWNLOADS: u32 = 1_000;

pub async fn grant(
    state: &AppState,
    owner: Uuid,
    file_id: Uuid,
    email: &str,
    client: &ClientMeta,
) -> AppResult<GrantResponse> {
    let file = load_authorized(state, owner, file_id, Action::Share).await?;
    require_available(file.status.as_str())?;

    let email = normalize_email(email)?;
    // Trade-off: this reveals to an authenticated user whether an email is registered. Most
    // sharing products accept that for usability (immediate "no such user" feedback); the
    // alternative is an invite flow that behaves identically either way.
    let grantee = users::repo::find_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::validation("no user with that email address"))?;
    if grantee.id == owner {
        return Err(AppError::validation("you already own this file"));
    }

    let created_at = repo::insert_grant(&state.db, file.id, grantee.id, owner).await?;
    AuditEvent::new("share.grant_created", Outcome::Success)
        .actor(owner)
        .target("file", file.id)
        .metadata(json!({ "grantee_id": grantee.id }))
        .record(&state.db, client)
        .await;
    Ok(GrantResponse {
        user_id: grantee.id,
        email: grantee.email,
        created_at,
    })
}

pub async fn list_grants(
    state: &AppState,
    owner: Uuid,
    file_id: Uuid,
) -> AppResult<Vec<GrantResponse>> {
    let file = load_authorized(state, owner, file_id, Action::Share).await?;
    Ok(repo::list_grants(&state.db, file.id)
        .await?
        .into_iter()
        .map(|g| GrantResponse {
            user_id: g.user_id,
            email: g.email,
            created_at: g.created_at,
        })
        .collect())
}

pub async fn revoke_grant(
    state: &AppState,
    owner: Uuid,
    file_id: Uuid,
    grantee_id: Uuid,
    client: &ClientMeta,
) -> AppResult<()> {
    let file = load_authorized(state, owner, file_id, Action::Share).await?;
    if !repo::delete_grant(&state.db, file.id, grantee_id).await? {
        return Err(AppError::NotFound);
    }
    AuditEvent::new("share.grant_revoked", Outcome::Success)
        .actor(owner)
        .target("file", file.id)
        .metadata(json!({ "grantee_id": grantee_id }))
        .record(&state.db, client)
        .await;
    Ok(())
}

pub async fn create_link(
    state: &AppState,
    owner: Uuid,
    file_id: Uuid,
    req: CreateShareLinkRequest,
    client: &ClientMeta,
) -> AppResult<CreatedShareLinkResponse> {
    let file = load_authorized(state, owner, file_id, Action::Share).await?;
    require_available(file.status.as_str())?;

    let ttl = req
        .expires_in_secs
        .map_or(DEFAULT_LINK_TTL, Duration::from_secs);
    if ttl.is_zero() || ttl > MAX_LINK_TTL {
        return Err(AppError::validation(
            "expires_in_secs must be between 1 second and 7 days",
        ));
    }
    let max_downloads = match req.max_downloads {
        Some(n) if n == 0 || n > MAX_LINK_DOWNLOADS => {
            return Err(AppError::validation(format!(
                "max_downloads must be between 1 and {MAX_LINK_DOWNLOADS}"
            )));
        }
        Some(n) => Some(i32::try_from(n).map_err(AppError::internal)?),
        None => None,
    };

    // 256-bit random token; only its SHA-256 is stored, so a database leak exposes no links.
    let token = tokens::generate_token();
    let expires_at = (Utc::now() + chrono::Duration::from_std(ttl).map_err(AppError::internal)?)
        .trunc_subsecs(6);
    let row = repo::insert_link(
        &state.db,
        file.id,
        owner,
        &tokens::hash_token(&token),
        expires_at,
        max_downloads,
    )
    .await?;

    AuditEvent::new("share.link_created", Outcome::Success)
        .actor(owner)
        .target("file", file.id)
        .metadata(
            json!({ "link_id": row.id, "expires_at": expires_at, "max_downloads": max_downloads }),
        )
        .record(&state.db, client)
        .await;
    Ok(CreatedShareLinkResponse {
        link: to_response(&row),
        token,
    })
}

pub async fn list_links(
    state: &AppState,
    owner: Uuid,
    file_id: Uuid,
) -> AppResult<Vec<ShareLinkResponse>> {
    let file = load_authorized(state, owner, file_id, Action::Share).await?;
    Ok(repo::list_links(&state.db, file.id)
        .await?
        .iter()
        .map(to_response)
        .collect())
}

pub async fn revoke_link(
    state: &AppState,
    owner: Uuid,
    file_id: Uuid,
    link_id: Uuid,
    client: &ClientMeta,
) -> AppResult<()> {
    let file = load_authorized(state, owner, file_id, Action::Share).await?;
    if !repo::revoke_link(&state.db, file.id, link_id).await? {
        return Err(AppError::NotFound);
    }
    AuditEvent::new("share.link_revoked", Outcome::Success)
        .actor(owner)
        .target("file", file.id)
        .metadata(json!({ "link_id": link_id }))
        .record(&state.db, client)
        .await;
    Ok(())
}

/// Anonymous download through a share link.
///
/// Unknown, expired, revoked and exhausted links all produce the same 404, so the response
/// never tells a guesser which tokens once existed.
pub async fn redeem(
    state: &AppState,
    token: &str,
    client: &ClientMeta,
) -> AppResult<DownloadResponse> {
    let Some((link_id, file_id)) = repo::redeem_link(&state.db, &tokens::hash_token(token)).await?
    else {
        AuditEvent::new("share.link_redeem", Outcome::Denied)
            .record(&state.db, client)
            .await;
        return Err(AppError::NotFound);
    };
    let file = files_repo::find_by_id(&state.db, file_id)
        .await?
        .filter(|f| f.status == STATUS_AVAILABLE)
        .ok_or(AppError::NotFound)?;

    // Even shorter TTL than owner downloads: a share link "download" is counted when the URL
    // is issued, so the URL itself must not be reusable for long.
    let request = state
        .storage
        .presign_get(
            GetObjectSpec {
                key: &file.object_key,
                download_filename: &file.filename,
                content_type: &file.content_type,
            },
            state.config.storage.share_download_url_ttl,
        )
        .await?;

    AuditEvent::new("share.link_redeem", Outcome::Success)
        .target("file", file.id)
        .metadata(json!({ "link_id": link_id }))
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_downloads_total", "via" => "share_link").increment(1);

    Ok(DownloadResponse {
        file_id: file.id,
        filename: file.filename.clone(),
        size_bytes: file.size(),
        sha256: hex::encode(&file.sha256),
        request: request.into(),
    })
}

fn require_available(status: &str) -> AppResult<()> {
    if status == STATUS_AVAILABLE {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "only available files can be shared".into(),
        ))
    }
}

fn to_response(row: &ShareLinkRow) -> ShareLinkResponse {
    ShareLinkResponse {
        id: row.id,
        file_id: row.file_id,
        expires_at: row.expires_at,
        max_downloads: row.max_downloads.and_then(|n| u32::try_from(n).ok()),
        download_count: u32::try_from(row.download_count).unwrap_or(0),
        revoked: row.revoked_at.is_some(),
        created_at: row.created_at,
    }
}
