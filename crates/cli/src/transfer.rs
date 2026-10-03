//! Uploading and downloading files: hashing, multipart concurrency, resume, verification.

use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use indicatif::{ProgressBar, ProgressStyle};
use securedrop_common::{
    CreateUploadRequest, DownloadResponse, FileResponse, PartChecksum, PresignedRequest,
    UploadInstructions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, sync::Semaphore, task::JoinSet};
use uuid::Uuid;

use crate::{client::ApiClient, credentials::write_private};

const HASH_BUFFER: usize = 1024 * 1024;
const PART_ATTEMPTS: u32 = 4;

#[derive(Debug, Clone)]
pub struct UploadOptions {
    pub content_type: Option<String>,
    /// Parts uploaded in parallel.
    pub concurrency: usize,
    /// Directory for resume state (normally the credential store dir).
    pub state_dir: PathBuf,
    /// Stop after uploading this many parts in this run (simulates an interruption; used by
    /// tests, and handy for demos).
    pub stop_after_parts: Option<usize>,
    pub progress: bool,
}

#[derive(Debug)]
pub enum UploadOutcome {
    Completed(FileResponse),
    /// Stopped early; run the same upload again to resume.
    Interrupted {
        file_id: Uuid,
        parts_remaining: usize,
    },
}

/// What we remember between runs so an interrupted multipart upload can continue.
#[derive(Debug, Serialize, Deserialize)]
struct ResumeState {
    api_url: String,
    file_id: Uuid,
    size: u64,
    sha256: String,
}

/// SHA-256 of a file, streamed in 1 MiB chunks (constant memory for any file size).
/// Runs on the blocking pool: it's CPU and disk bound, not async work.
pub async fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut file =
            std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; HASH_BUFFER];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    })
    .await?
}

pub async fn upload(
    client: &ApiClient,
    path: &Path,
    opts: &UploadOptions,
) -> anyhow::Result<UploadOutcome> {
    let size = tokio::fs::metadata(path).await?.len();
    if size == 0 {
        bail!("refusing to upload an empty file");
    }
    let sha256 = sha256_file(path).await?;
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("file name is not valid UTF-8")?
        .to_string();
    let content_type = opts
        .content_type
        .clone()
        .unwrap_or_else(|| guess_content_type(&filename).into());

    let state_path = opts
        .state_dir
        .join("uploads")
        .join(format!("{sha256}.json"));

    // Resume an earlier attempt for the same bytes against the same server, if possible.
    if let Some(state) = read_state(&state_path)
        && state.api_url == client.base_url()
        && state.size == size
        && let Ok(progress) = client.upload_progress(state.file_id).await
    {
        if opts.progress {
            eprintln!(
                "resuming upload {} ({} of {} parts already uploaded)",
                state.file_id,
                progress.uploaded_parts.len(),
                progress.part_count
            );
        }
        return upload_parts(
            client,
            path,
            state.file_id,
            progress.part_size,
            progress.part_count,
            progress.missing_parts,
            &state_path,
            opts,
        )
        .await;
    }

    let created = client
        .create_upload(&CreateUploadRequest {
            filename,
            content_type,
            size_bytes: size,
            sha256: sha256.clone(),
        })
        .await?;

    match created.upload {
        UploadInstructions::Single { request } => {
            let body = tokio::fs::read(path).await?;
            put_with_retry(client.http(), &request, body).await?;
            Ok(UploadOutcome::Completed(
                client.complete_upload(created.file_id).await?,
            ))
        }
        UploadInstructions::Multipart {
            part_size,
            part_count,
        } => {
            write_private(
                &state_path,
                &serde_json::to_vec(&ResumeState {
                    api_url: client.base_url().to_string(),
                    file_id: created.file_id,
                    size,
                    sha256,
                })?,
            )?;
            upload_parts(
                client,
                path,
                created.file_id,
                part_size,
                part_count,
                (1..=part_count).collect(),
                &state_path,
                opts,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_parts(
    client: &ApiClient,
    path: &Path,
    file_id: Uuid,
    part_size: u64,
    part_count: u32,
    missing: Vec<u32>,
    state_path: &Path,
    opts: &UploadOptions,
) -> anyhow::Result<UploadOutcome> {
    let size = tokio::fs::metadata(path).await?.len();
    let to_send: Vec<u32> = match opts.stop_after_parts {
        Some(limit) => missing.iter().copied().take(limit).collect(),
        None => missing.clone(),
    };

    let bar = progress_bar(opts.progress, u64::from(part_count));
    bar.set_position(u64::from(part_count) - missing.len() as u64);

    // Bounded parallelism: at most `concurrency` parts are in memory/in flight at once.
    let permits = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for part_number in to_send.iter().copied() {
        let permit = permits.clone().acquire_owned().await?;
        let offset = u64::from(part_number - 1) * part_size;
        let len = part_size.min(size - offset);
        let bytes = read_range(path, offset, len).await?;
        let digest = hex::encode(Sha256::digest(&bytes));

        // Ask for this part's URL with its checksum: the URL only accepts these exact bytes.
        let presigned = client
            .presign_parts(
                file_id,
                vec![PartChecksum {
                    part_number,
                    sha256: digest,
                }],
            )
            .await?
            .parts
            .pop()
            .context("server returned no part URL")?;

        let http = client.http().clone();
        let bar = bar.clone();
        tasks.spawn(async move {
            let _permit = permit;
            put_with_retry(&http, &presigned.request, bytes).await?;
            bar.inc(1);
            anyhow::Ok(part_number)
        });

        // Reap finished uploads as we go, surfacing the first error promptly.
        while let Some(done) = tasks.try_join_next() {
            done??;
        }
    }
    while let Some(done) = tasks.join_next().await {
        done??;
    }
    bar.finish_and_clear();

    let sent: BTreeSet<u32> = to_send.iter().copied().collect();
    let remaining = missing.iter().filter(|n| !sent.contains(n)).count();
    if remaining > 0 {
        return Ok(UploadOutcome::Interrupted {
            file_id,
            parts_remaining: remaining,
        });
    }

    let file = client.complete_upload(file_id).await?;
    let _ = std::fs::remove_file(state_path);
    Ok(UploadOutcome::Completed(file))
}

/// PUT to a presigned URL with exponential backoff on transient failures (network errors,
/// 5xx, 429). 4xx responses (bad signature, wrong checksum) are permanent and not retried.
async fn put_with_retry(
    http: &reqwest::Client,
    req: &PresignedRequest,
    body: Vec<u8>,
) -> anyhow::Result<()> {
    let mut delay = Duration::from_millis(250);
    for attempt in 1..=PART_ATTEMPTS {
        let mut builder = http.request(
            reqwest::Method::from_bytes(req.method.as_bytes())?,
            &req.url,
        );
        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }
        match builder.body(body.clone()).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp)
                if resp.status().is_client_error()
                    && resp.status() != reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                bail!(
                    "storage rejected the upload ({status}): {}",
                    text.chars().take(300).collect::<String>()
                );
            }
            Ok(resp) if attempt == PART_ATTEMPTS => {
                bail!("storage error {} after {attempt} attempts", resp.status())
            }
            Err(err) if attempt == PART_ATTEMPTS => return Err(err).context("upload failed"),
            _ => {}
        }
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
    unreachable!("loop returns on the last attempt")
}

/// Download via a presigned URL, hashing while streaming to a temporary file, and only move it
/// into place if the SHA-256 matches. A corrupted or tampered download never appears at `dest`.
pub async fn download_to(
    client: &ApiClient,
    info: &DownloadResponse,
    dest: &Path,
    overwrite: bool,
    progress: bool,
) -> anyhow::Result<PathBuf> {
    if dest.exists() && !overwrite {
        bail!(
            "{} already exists (use --force to overwrite)",
            dest.display()
        );
    }
    let tmp = dest.with_extension("securedrop-partial");
    let mut out = tokio::fs::File::create(&tmp).await?;
    let mut hasher = Sha256::new();

    let mut builder = client.http().get(&info.request.url);
    for (name, value) in &info.request.headers {
        builder = builder.header(name, value);
    }
    let mut resp = builder
        .send()
        .await?
        .error_for_status()
        .context("download failed")?;
    let bar = progress_bar(progress, info.size_bytes);
    while let Some(chunk) = resp.chunk().await? {
        hasher.update(&chunk);
        out.write_all(&chunk).await?;
        bar.inc(chunk.len() as u64);
    }
    out.flush().await?;
    out.sync_all().await?;
    drop(out);
    bar.finish_and_clear();

    let actual = hex::encode(hasher.finalize());
    if actual != info.sha256 {
        let _ = tokio::fs::remove_file(&tmp).await;
        bail!(
            "integrity check failed: expected sha256 {}, got {actual}",
            info.sha256
        );
    }
    tokio::fs::rename(&tmp, dest).await?;
    Ok(dest.to_path_buf())
}

/// Pick a local filename from the server-provided one, defensively (basename only).
pub fn safe_local_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != ':')
        .collect();
    match cleaned.trim() {
        "" | "." | ".." => "download.bin".into(),
        other => other.to_string(),
    }
}

pub fn guess_content_type(filename: &str) -> &'static str {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
}

async fn read_range(path: &Path, offset: u64, len: u64) -> anyhow::Result<Vec<u8>> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; usize::try_from(len)?];
        file.read_exact(&mut buf)?;
        Ok(buf)
    })
    .await?
}

fn read_state(path: &Path) -> Option<ResumeState> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn progress_bar(enabled: bool, len: u64) -> ProgressBar {
    if !enabled {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(len);
    if let Ok(style) = ProgressStyle::with_template("{bar:40} {pos}/{len} {elapsed_precise} {msg}")
    {
        bar.set_style(style);
    }
    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names_are_basenames() {
        assert_eq!(safe_local_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_local_name("C:\\x\\y.txt"), "y.txt");
        assert_eq!(safe_local_name(".."), "download.bin");
        assert_eq!(safe_local_name("a:b.txt"), "ab.txt");
    }

    #[test]
    fn content_type_guessing() {
        assert_eq!(guess_content_type("Report.PDF"), "application/pdf");
        assert_eq!(guess_content_type("noext"), "application/octet-stream");
    }

    #[tokio::test]
    async fn sha256_of_file_matches_in_memory_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        assert_eq!(
            sha256_file(&path).await.unwrap(),
            hex::encode(Sha256::digest(&data))
        );
    }
}
