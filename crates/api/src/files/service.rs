//! Upload and download business logic.
//!
//! The flow, from the client's point of view:
//! 1. `POST /uploads` declares name, type, size and SHA-256 → we validate, reserve quota,
//!    create a `pending` row, and return a presigned PUT (small files) or multipart
//!    instructions (large files).
//! 2. The client sends the bytes **directly to S3** (one PUT, or one PUT per part).
//! 3. `POST /uploads/{id}/complete` → we ask S3 what actually arrived (HEAD/ListParts with
//!    checksums, a 512-byte ranged GET for sniffing) and only then mark the file `available`.

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use securedrop_common::{
    CreateUploadRequest, CreateUploadResponse, DownloadResponse, FileListResponse, FileResponse,
    PresignPartsRequest, PresignPartsResponse, PresignedPart, UploadInstructions,
    UploadProgressResponse, UploadedPartInfo,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    authz::{Action, load_authorized},
    model::{self, FileRecord, KIND_MULTIPART, KIND_SINGLE, STATUS_AVAILABLE, STATUS_PENDING},
    repo,
    validation::{self, SNIFF_LEN},
};
use crate::{
    audit::{AuditEvent, Outcome},
    error::{AppError, AppResult},
    middleware::client_meta::ClientMeta,
    state::AppState,
    storage::{CompleteOutcome, GetObjectSpec, PutObjectSpec, UploadPartSpec, UploadedPart},
    users,
};

/// Clients may request at most this many part URLs per call (bounds response size and work).
const MAX_PARTS_PER_PRESIGN: usize = 100;

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
    let size = i64::try_from(req.size_bytes).map_err(AppError::internal)?;
    let multipart = req.size_bytes > policy.single_part_max;

    let file_id = Uuid::now_v7();
    let object_key = model::object_key(user_id, file_id);
    let expires_at = Utc::now()
        + chrono::Duration::from_std(policy.pending_upload_ttl).map_err(AppError::internal)?;

    // For multipart we need S3's upload id before inserting the row. This network call happens
    // before we take any database locks.
    let (upload_kind, s3_upload_id, part_size, part_count) = if multipart {
        let part_count = req.size_bytes.div_ceil(policy.part_size);
        let upload_id = state
            .storage
            .create_multipart(&object_key, &content_type)
            .await?;
        (
            KIND_MULTIPART,
            Some(upload_id),
            Some(i64::try_from(policy.part_size).map_err(AppError::internal)?),
            Some(i32::try_from(part_count).map_err(AppError::internal)?),
        )
    } else {
        (KIND_SINGLE, None, None, None)
    };

    // Quota check and reservation happen in one transaction while holding a lock on the user's
    // row. Without the lock, two parallel requests could each see "9 GB used of 10 GB" and both
    // reserve 1 GB.
    let reserved = async {
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
                upload_kind,
                s3_upload_id: s3_upload_id.as_deref(),
                part_size,
                part_count,
                upload_expires_at: expires_at,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(file)
    }
    .await;

    let file = match reserved {
        Ok(file) => file,
        Err(err) => {
            // Don't leave an orphaned multipart upload behind (it would be billed as storage).
            if let Some(upload_id) = &s3_upload_id
                && let Err(abort_err) = state.storage.abort_multipart(&object_key, upload_id).await
            {
                tracing::warn!(
                    error = format!("{abort_err:#}"),
                    "failed to abort orphaned multipart upload"
                );
            }
            return Err(err);
        }
    };

    let upload = match (part_size, part_count) {
        (Some(part_size), Some(part_count)) => UploadInstructions::Multipart {
            part_size: u64::try_from(part_size).map_err(AppError::internal)?,
            part_count: u32::try_from(part_count).map_err(AppError::internal)?,
        },
        _ => {
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
            UploadInstructions::Single {
                request: request.into(),
            }
        }
    };

    AuditEvent::new("file.upload_started", Outcome::Success)
        .actor(user_id)
        .target("file", file.id)
        .metadata(json!({ "size_bytes": size, "content_type": content_type, "kind": upload_kind }))
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_uploads_total", "stage" => "started", "kind" => upload_kind)
        .increment(1);

    Ok(CreateUploadResponse {
        file_id: file.id,
        upload,
        upload_expires_at: file.upload_expires_at,
    })
}

/// Issue presigned URLs for specific parts of a multipart upload.
///
/// The client declares each part's SHA-256 *before* uploading it; we record it and sign it into
/// the part URL, so S3 rejects a part whose bytes don't match. The client can ask again for any
/// part at any time, which is what makes uploads resumable after a crash or URL expiry.
pub async fn presign_parts(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    req: PresignPartsRequest,
) -> AppResult<PresignPartsResponse> {
    let file = load_authorized(state, user_id, file_id, Action::ManageUpload).await?;
    let (upload_id, part_size, part_count) = pending_multipart(&file)?;

    if req.parts.is_empty() || req.parts.len() > MAX_PARTS_PER_PRESIGN {
        return Err(AppError::validation(format!(
            "request between 1 and {MAX_PARTS_PER_PRESIGN} parts at a time"
        )));
    }

    let mut out = Vec::with_capacity(req.parts.len());
    for part in &req.parts {
        if part.part_number == 0 || part.part_number > part_count {
            return Err(AppError::validation(format!(
                "part_number must be between 1 and {part_count}"
            )));
        }
        let sha256 = validation::parse_sha256_hex(&part.sha256)?;
        let size = expected_part_size(file.size(), part_size, part_count, part.part_number);

        repo::upsert_part(
            &state.db,
            file.id,
            i32::try_from(part.part_number).map_err(AppError::internal)?,
            &sha256,
            i64::try_from(size).map_err(AppError::internal)?,
        )
        .await?;

        let request = state
            .storage
            .presign_upload_part(
                UploadPartSpec {
                    key: &file.object_key,
                    upload_id,
                    part_number: part.part_number,
                    size,
                    sha256_b64: &STANDARD.encode(sha256),
                },
                state.config.storage.upload_url_ttl,
            )
            .await?;
        out.push(PresignedPart {
            part_number: part.part_number,
            size_bytes: size,
            request: request.into(),
        });
    }
    Ok(PresignPartsResponse { parts: out })
}

/// Which parts has S3 received? The source of truth is S3 itself (ListParts), not the client.
pub async fn upload_progress(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
) -> AppResult<UploadProgressResponse> {
    let file = load_authorized(state, user_id, file_id, Action::ManageUpload).await?;
    let (upload_id, part_size, part_count) = pending_multipart(&file)?;

    let uploaded = state
        .storage
        .list_parts(&file.object_key, upload_id)
        .await?
        .ok_or_else(|| AppError::Conflict("the multipart upload no longer exists".into()))?;
    let have: BTreeSet<u32> = uploaded.iter().map(|p| p.part_number).collect();

    Ok(UploadProgressResponse {
        file_id: file.id,
        status: file.status(),
        part_size,
        part_count,
        uploaded_parts: uploaded
            .iter()
            .map(|p| UploadedPartInfo {
                part_number: p.part_number,
                size_bytes: p.size,
            })
            .collect(),
        missing_parts: (1..=part_count).filter(|n| !have.contains(n)).collect(),
        upload_expires_at: file.upload_expires_at,
    })
}

pub async fn complete_upload(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    client: &ClientMeta,
) -> AppResult<FileResponse> {
    let file = load_authorized(state, user_id, file_id, Action::ManageUpload).await?;
    match file.status.as_str() {
        // Idempotent: retrying "complete" after a network blip is safe.
        STATUS_AVAILABLE => return Ok(file.to_response()),
        STATUS_PENDING => {}
        _ => return Err(AppError::Conflict("upload is no longer pending".into())),
    }

    if file.upload_kind == KIND_MULTIPART {
        assemble_multipart(state, &file, client).await?;
    }

    let info = state.storage.head(&file.object_key).await?.ok_or_else(|| {
        AppError::Conflict("the file has not been uploaded to storage yet".into())
    })?;

    // 1. Size: what arrived must be exactly what was declared (and quota-reserved).
    if info.size != file.size() {
        return Err(fail_upload(state, &file, client, "size mismatch").await);
    }

    // 2. Integrity. Single-part: S3 verified the body against the SHA-256 signed into the URL;
    //    we re-check the stored value. Multipart: S3 stores a *composite* checksum (a hash of
    //    the part hashes), which assemble_multipart already verified part by part.
    if file.upload_kind == KIND_SINGLE {
        let expected = STANDARD.encode(&file.sha256);
        if info.checksum_sha256.as_deref() != Some(expected.as_str()) {
            return Err(fail_upload(state, &file, client, "checksum mismatch").await);
        }
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
        return load_authorized(state, user_id, file_id, Action::ViewMetadata)
            .await
            .map(|f| f.to_response());
    };

    AuditEvent::new("file.upload_completed", Outcome::Success)
        .actor(user_id)
        .target("file", file.id)
        .metadata(json!({ "size_bytes": file.size_bytes, "kind": file.upload_kind }))
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_uploads_total", "stage" => "completed", "kind" => file.upload_kind.clone())
        .increment(1);
    Ok(done.to_response())
}

/// Verify every part against what the client declared, then ask S3 to assemble the object.
async fn assemble_multipart(
    state: &AppState,
    file: &FileRecord,
    client: &ClientMeta,
) -> AppResult<()> {
    let (upload_id, part_size, part_count) = pending_multipart(file)?;

    let Some(uploaded) = state
        .storage
        .list_parts(&file.object_key, upload_id)
        .await?
    else {
        // Already completed by an earlier attempt that died before updating the database.
        return Ok(());
    };
    let declared: BTreeMap<u32, Vec<u8>> = repo::declared_parts(&state.db, file.id)
        .await?
        .into_iter()
        .filter_map(|p| u32::try_from(p.part_number).ok().map(|n| (n, p.sha256)))
        .collect();

    let have: BTreeSet<u32> = uploaded.iter().map(|p| p.part_number).collect();
    let missing: Vec<u32> = (1..=part_count).filter(|n| !have.contains(n)).collect();
    if !missing.is_empty() {
        // Not a failure: the client can upload the rest and try again.
        return Err(AppError::Conflict(format!(
            "parts not yet uploaded: {missing:?}"
        )));
    }

    let mut parts: Vec<UploadedPart> = Vec::with_capacity(uploaded.len());
    for part in uploaded {
        if part.part_number > part_count {
            return Err(fail_upload(state, file, client, "unexpected extra part").await);
        }
        if part.size != expected_part_size(file.size(), part_size, part_count, part.part_number) {
            return Err(fail_upload(state, file, client, "part size mismatch").await);
        }
        // Each part's bytes were verified by S3 against the SHA-256 signed into its URL. Now
        // make sure the stored part is the one the client declared to us:
        //  * AWS S3 returns each part's checksum in ListParts, so compare directly;
        //  * some S3-compatible stores (e.g. RustFS) omit it, so we fall back on the composite
        //    checksum check below.
        let Some(expected) = declared.get(&part.part_number).map(|h| STANDARD.encode(h)) else {
            return Err(fail_upload(state, file, client, "part was never declared").await);
        };
        if part
            .checksum_sha256
            .as_ref()
            .is_some_and(|actual| *actual != expected)
        {
            return Err(fail_upload(state, file, client, "part checksum mismatch").await);
        }
        // Complete with the *declared* checksums: S3 itself rejects the request if any of
        // them differs from the checksum of the part it stored.
        parts.push(UploadedPart {
            checksum_sha256: Some(expected),
            ..part
        });
    }

    let reported = match state
        .storage
        .complete_multipart(&file.object_key, upload_id, &parts)
        .await?
    {
        CompleteOutcome::Completed { checksum_sha256 } => checksum_sha256,
        CompleteOutcome::Rejected { code } => {
            let reason = format!("storage rejected the parts ({code})");
            return Err(fail_upload(state, file, client, &reason).await);
        }
    };
    // The composite checksum is SHA-256 over the part digests. If it matches the one computed
    // from the declared digests, every stored part is exactly the part the client declared.
    let ours = composite_checksum(&parts);
    let matches = reported
        .as_deref()
        .is_some_and(|r| r == ours || Some(r) == ours.split('-').next());
    if !matches {
        return Err(fail_upload(state, file, client, "composite checksum mismatch").await);
    }
    Ok(())
}

/// Abort an in-progress upload (single or multipart) and release its quota.
pub async fn abort_upload(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    client: &ClientMeta,
) -> AppResult<()> {
    let file = load_authorized(state, user_id, file_id, Action::ManageUpload).await?;
    if file.status != STATUS_PENDING {
        return Err(AppError::Conflict("upload is not pending".into()));
    }
    if !repo::mark_failed(&state.db, file.id).await? {
        return Err(AppError::Conflict("upload is not pending".into()));
    }
    purge_storage(
        state,
        file.id,
        &file.object_key,
        file.s3_upload_id.as_deref(),
    )
    .await;
    AuditEvent::new("file.upload_aborted", Outcome::Success)
        .actor(user_id)
        .target("file", file.id)
        .record(&state.db, client)
        .await;
    Ok(())
}

/// Delete a file: hide it immediately, then remove the bytes. If the S3 delete fails, the
/// row is still `deleted` (inaccessible) and the cleanup worker finishes the purge.
pub async fn delete_file(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    client: &ClientMeta,
) -> AppResult<()> {
    let file = load_authorized(state, user_id, file_id, Action::Delete).await?;
    if file.status == STATUS_PENDING {
        return Err(AppError::Conflict(
            "abort the upload instead (DELETE /uploads/{id})".into(),
        ));
    }
    if !repo::mark_deleted(&state.db, file.id).await? {
        return Err(AppError::NotFound);
    }
    purge_storage(state, file.id, &file.object_key, None).await;
    AuditEvent::new("file.deleted", Outcome::Success)
        .actor(user_id)
        .target("file", file.id)
        .record(&state.db, client)
        .await;
    Ok(())
}

pub const DEFAULT_PAGE_SIZE: i64 = 50;
pub const MAX_PAGE_SIZE: i64 = 200;

pub async fn list_files(
    state: &AppState,
    user_id: Uuid,
    shared: bool,
    before: Option<Uuid>,
    limit: Option<i64>,
) -> AppResult<FileListResponse> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    // Fetch one extra row to learn whether another page exists.
    let mut rows = if shared {
        repo::list_shared_with(&state.db, user_id, before, limit + 1).await?
    } else {
        repo::list_owned(&state.db, user_id, before, limit + 1).await?
    };
    let has_more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit;
    rows.truncate(usize::try_from(limit).unwrap_or(0));
    Ok(FileListResponse {
        next_cursor: if has_more {
            rows.last().map(|f| f.id)
        } else {
            None
        },
        files: rows.iter().map(FileRecord::to_response).collect(),
    })
}

pub async fn get_file(state: &AppState, user_id: Uuid, file_id: Uuid) -> AppResult<FileResponse> {
    Ok(
        load_authorized(state, user_id, file_id, Action::ViewMetadata)
            .await?
            .to_response(),
    )
}

pub async fn download(
    state: &AppState,
    user_id: Uuid,
    file_id: Uuid,
    client: &ClientMeta,
) -> AppResult<DownloadResponse> {
    let file = load_authorized(state, user_id, file_id, Action::Download).await?;
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
    let via = if file.owner_id == user_id {
        "owner"
    } else {
        "grant"
    };
    metrics::counter!("securedrop_downloads_total", "via" => via).increment(1);

    Ok(DownloadResponse {
        file_id: file.id,
        filename: file.filename.clone(),
        size_bytes: file.size(),
        sha256: hex::encode(&file.sha256),
        request: request.into(),
    })
}

/// The multipart fields of a pending multipart upload, or a 409 if it isn't one.
fn pending_multipart(file: &FileRecord) -> AppResult<(&str, u64, u32)> {
    if file.status != STATUS_PENDING {
        return Err(AppError::Conflict("upload is not pending".into()));
    }
    match (&file.s3_upload_id, file.part_size, file.part_count) {
        (Some(upload_id), Some(size), Some(count)) => Ok((
            upload_id.as_str(),
            u64::try_from(size).map_err(AppError::internal)?,
            u32::try_from(count).map_err(AppError::internal)?,
        )),
        _ => Err(AppError::Conflict("this is not a multipart upload".into())),
    }
}

/// Every part is `part_size` bytes except the last, which holds the remainder.
pub fn expected_part_size(total: u64, part_size: u64, part_count: u32, part_number: u32) -> u64 {
    if part_number < part_count {
        part_size
    } else {
        total - part_size * u64::from(part_count - 1)
    }
}

/// S3's composite checksum for multipart objects: SHA-256 over the concatenated *raw* part
/// digests, base64-encoded, suffixed with `-<number of parts>`.
pub fn composite_checksum(parts: &[UploadedPart]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        if let Some(b64) = &part.checksum_sha256
            && let Ok(raw) = STANDARD.decode(b64)
        {
            hasher.update(raw);
        }
    }
    format!("{}-{}", STANDARD.encode(hasher.finalize()), parts.len())
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
    purge_storage(
        state,
        file.id,
        &file.object_key,
        file.s3_upload_id.as_deref(),
    )
    .await;
    AuditEvent::new("file.upload_rejected", Outcome::Failure)
        .actor(file.owner_id)
        .target("file", file.id)
        .metadata(json!({ "reason": reason }))
        .record(&state.db, client)
        .await;
    metrics::counter!("securedrop_uploads_total", "stage" => "rejected", "kind" => file.upload_kind.clone())
        .increment(1);
    AppError::IntegrityCheckFailed(reason.to_string())
}

/// Remove an upload's data from storage: abort the multipart upload (if any) and delete the
/// object (in case a multipart upload had already been assembled).
pub async fn purge_objects(
    state: &AppState,
    object_key: &str,
    s3_upload_id: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(upload_id) = s3_upload_id {
        state.storage.abort_multipart(object_key, upload_id).await?;
    }
    state.storage.delete(object_key).await
}

/// Best-effort purge used on the request path. If anything fails, `purged_at` stays NULL and
/// the cleanup worker retries later.
async fn purge_storage(
    state: &AppState,
    file_id: Uuid,
    object_key: &str,
    s3_upload_id: Option<&str>,
) {
    match purge_objects(state, object_key, s3_upload_id).await {
        Ok(()) => {
            if let Err(err) = repo::mark_purged(&state.db, file_id).await {
                tracing::warn!(%err, %file_id, "failed to mark file purged");
            }
        }
        Err(err) => {
            tracing::warn!(error = format!("{err:#}"), %file_id, "failed to purge storage; will retry")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_sizes_cover_the_file_exactly() {
        let (total, part, count) = (12 * 1024 * 1024 + 7, 5 * 1024 * 1024, 3);
        let sizes: Vec<u64> = (1..=count)
            .map(|n| expected_part_size(total, part, count, n))
            .collect();
        assert_eq!(sizes, vec![part, part, 2 * 1024 * 1024 + 7]);
        assert_eq!(sizes.iter().sum::<u64>(), total);
    }

    #[test]
    fn composite_checksum_matches_s3_definition() {
        let part = |n: u32, data: &[u8]| UploadedPart {
            part_number: n,
            size: data.len() as u64,
            etag: String::new(),
            checksum_sha256: Some(STANDARD.encode(Sha256::digest(data))),
        };
        let parts = [part(1, b"hello "), part(2, b"world")];
        let mut concat = Vec::new();
        concat.extend_from_slice(&Sha256::digest(b"hello "));
        concat.extend_from_slice(&Sha256::digest(b"world"));
        let expected = format!("{}-2", STANDARD.encode(Sha256::digest(&concat)));
        assert_eq!(composite_checksum(&parts), expected);
    }
}
