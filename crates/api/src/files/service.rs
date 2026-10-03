//! Upload and download business logic.
//!
//! The flow, from the client's point of view:
//! 1. `POST /uploads` declares name, type, size and SHA-256 → we validate, reserve quota,
//!    create a `pending` row, and return a presigned PUT (or multipart instructions).
//! 2. The client PUTs the bytes **directly to S3**.
//! 3. `POST /uploads/{id}/complete` → we ask S3 what actually arrived (HEAD with checksums,
//!    a 512-byte ranged GET for sniffing) and only then mark the file `available`.

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use securedrop_common::{
    CreateUploadRequest, CreateUploadResponse, DownloadResponse, FileResponse, UploadInstructions,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    model::{self, FileRecord, KIND_SINGLE, STATUS_AVAILABLE, STATUS_PENDING},
    repo,
    validation::{self, SNIFF_LEN},
};
use crate::{
    audit::{AuditEvent, Outcome},
    error::{AppError, AppResult},
    middleware::client_meta::ClientMeta,
    state::AppState,
    storage::{GetObjectSpec, PutObjectSpec},
    users,
};

pub async fn create_upload(
    state: &AppState,
    user_id: Uuid,
    req: CreateUploadRequest,
    client: &ClientMeta,
) -> AppResult<CreateUploadResponse> {
    let policy = &state.config.uploads;

    let filename = validation::sanitize_filename(&req.filename)?;
    let content_type =
        validation::validate_content_type(&req.content_type, &policy.allowed_content_types)?;
    let sha256 = validation::parse_sha256_hex(&req.sha256)?;
    if req.size_bytes == 0 {
        return Err(AppError::validation("empty files cannot be uploaded"));
    }
    if req.size_bytes > policy.max_file_size {
        return Err(AppError::PayloadTooLarge(format!(
            "files may be at most {} bytes",
            policy.max_file_size
        )));
    }
    if req.size_bytes > policy.single_part_max {
        return Err(AppError::validation("multipart uploads are not enabled"));
    }
    let size = i64::try_from(req.size_bytes).map_err(AppError::internal)?;

    let file_id = Uuid::now_v7();
    let object_key = model::object_key(user_id, file_id);
    let expires_at = Utc::now()
        + chrono::Duration::from_std(policy.pending_upload_ttl).map_err(AppError::internal)?;

    // Quota check and reservation happen in one transaction while holding a lock on the user's
    // row. Without the lock, two parallel requests could each see "9 GB used of 10 GB" and both
    // reserve 1 GB.
    let mut tx = state.db.begin().await?;
    let quota = repo::lock_user_quota(&mut *tx, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let used = users::repo::storage_used(&mut *tx, user_id).await?;
    if used.saturating_add(size) > quota {
        return Err(AppError::QuotaExceeded);
    }
    let file = repo::insert(
        &mut *tx,
        repo::NewFile {
            id: file_id,
            owner_id: user_id,
            filename: &filename,
            content_type: &content_type,
            size_bytes: size,
            sha256: &sha256,
            object_key: &object_key,
            upload_kind: KIND_SINGLE,
            s3_upload_id: None,
            part_size: None,
            part_count: None,
            upload_expires_at: expires_at,
        },
    )
    .await?;
    tx.commit().await?;

    // Sign after committing: never hold row locks across calls to other systems.
    let request = state
        .storage
        .presign_put(
            PutObjectSpec {
                key: &object_key,
                size: req.size_bytes,
                sha256_b64: &STANDARD.encode(sha256),
                content_type: &content_type,
            },
            state.config.storage.upload_url_ttl,
        )
        .await?;

    AuditEvent::new("file.upload_started", Outcome::Success)
        .actor(user_id)
        .target("file", file.id)
        .metadata(json!({ "size_bytes": size, "content_type": content_type, "kind": KIND_SINGLE }))
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_uploads_total", "stage" => "started").increment(1);

    Ok(CreateUploadResponse {
        file_id: file.id,
        upload: UploadInstructions::Single {
            request: request.into(),
        },
        upload_expires_at: file.upload_expires_at,
    })
}

pub async fn complete_upload(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    client: &ClientMeta,
) -> AppResult<FileResponse> {
    let file = load_owned(state, user_id, file_id).await?;
    match file.status.as_str() {
        // Idempotent: retrying "complete" after a network blip is safe.
        STATUS_AVAILABLE => return Ok(file.to_response()),
        STATUS_PENDING => {}
        _ => return Err(AppError::Conflict("upload is no longer pending".into())),
    }

    let info = state.storage.head(&file.object_key).await?.ok_or_else(|| {
        AppError::Conflict("the file has not been uploaded to storage yet".into())
    })?;

    // 1. Size: what arrived must be exactly what was declared (and quota-reserved).
    if info.size != file.size() {
        return Err(fail_upload(state, &file, client, "size mismatch").await);
    }

    // 2. Integrity: S3 verified the body against the SHA-256 signed into the upload URL and
    //    stored it. We re-check that the stored checksum is the one we expect.
    let expected = STANDARD.encode(&file.sha256);
    if info.checksum_sha256.as_deref() != Some(expected.as_str()) {
        return Err(fail_upload(state, &file, client, "checksum mismatch").await);
    }

    // 3. Content sniffing on the first bytes only.
    let prefix = state
        .storage
        .read_prefix(&file.object_key, SNIFF_LEN.min(file.size()))
        .await?;
    if let Err(reason) = validation::check_magic_bytes(&file.content_type, &prefix) {
        return Err(fail_upload(state, &file, client, &reason).await);
    }

    let Some(done) =
        repo::mark_available(&state.db, file.id, info.checksum_sha256.as_deref()).await?
    else {
        // Lost a race with a concurrent complete/cleanup; report the current state.
        return load_owned(state, user_id, file_id)
            .await
            .map(|f| f.to_response());
    };

    AuditEvent::new("file.upload_completed", Outcome::Success)
        .actor(user_id)
        .target("file", file.id)
        .metadata(json!({ "size_bytes": file.size_bytes }))
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_uploads_total", "stage" => "completed").increment(1);
    Ok(done.to_response())
}

pub async fn get_file(state: &AppState, user_id: Uuid, file_id: Uuid) -> AppResult<FileResponse> {
    Ok(load_owned(state, user_id, file_id).await?.to_response())
}

pub async fn download(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    client: &ClientMeta,
) -> AppResult<DownloadResponse> {
    let file = load_owned(state, user_id, file_id).await?;
    if file.status != STATUS_AVAILABLE {
        return Err(AppError::Conflict(
            "file is not available for download".into(),
        ));
    }
    let request = state
        .storage
        .presign_get(
            GetObjectSpec {
                key: &file.object_key,
                download_filename: &file.filename,
                content_type: &file.content_type,
            },
            state.config.storage.download_url_ttl,
        )
        .await?;

    AuditEvent::new("file.download_url_issued", Outcome::Success)
        .actor(user_id)
        .target("file", file.id)
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_downloads_total", "via" => "owner").increment(1);

    Ok(DownloadResponse {
        file_id: file.id,
        filename: file.filename.clone(),
        size_bytes: file.size(),
        sha256: hex::encode(&file.sha256),
        request: request.into(),
    })
}

/// Phase 03 authorization: owners only. A file that exists but belongs to someone else is
/// reported as 404, exactly like a file that does not exist (no existence oracle).
async fn load_owned(state: &AppState, user_id: Uuid, file_id: Uuid) -> AppResult<FileRecord> {
    match repo::find_by_id(&state.db, file_id).await? {
        Some(file) if file.owner_id == user_id => Ok(file),
        _ => Err(AppError::NotFound),
    }
}

/// Mark an upload failed, delete whatever was uploaded, and audit why.
async fn fail_upload(
    state: &AppState,
    file: &FileRecord,
    client: &ClientMeta,
    reason: &str,
) -> AppError {
    if let Err(err) = repo::mark_failed(&state.db, file.id).await {
        return err.into();
    }
    match state.storage.delete(&file.object_key).await {
        Ok(()) => {
            if let Err(err) = repo::mark_purged(&state.db, file.id).await {
                tracing::warn!(%err, file_id = %file.id, "failed to mark purged");
            }
        }
        // Not fatal: the cleanup worker retries purging failed files.
        Err(err) => {
            tracing::warn!(error = format!("{err:#}"), file_id = %file.id, "failed to delete rejected object")
        }
    }
    AuditEvent::new("file.upload_rejected", Outcome::Failure)
        .actor(file.owner_id)
        .target("file", file.id)
        .metadata(json!({ "reason": reason }))
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_uploads_total", "stage" => "rejected").increment(1);
    AppError::IntegrityCheckFailed(reason.to_string())
}
