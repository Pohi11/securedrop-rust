//! Amazon S3 (or any S3-compatible store) implementation of [`ObjectStore`].

use std::{collections::BTreeMap, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{
    Client,
    config::{RequestChecksumCalculation, ResponseChecksumValidation},
    presigning::PresigningConfig,
    types::{
        ChecksumAlgorithm, ChecksumMode, CompletedMultipartUpload, CompletedPart,
        ServerSideEncryption,
    },
};
use chrono::Utc;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use super::{
    CompleteOutcome, GetObjectSpec, ObjectInfo, ObjectStore, PresignedRequest, PutObjectSpec,
    UploadPartSpec, UploadedPart,
};
use crate::config::StorageConfig;

#[derive(Clone)]
pub struct S3Store {
    /// Used for calls the API makes itself (HEAD, DELETE, ListParts...).
    client: Client,
    /// Used only to sign URLs handed to clients. Differs from `client` only when the store is
    /// reached through a different hostname from outside (local Docker setup).
    presign_client: Client,
    bucket: String,
    sse_kms_key_id: Option<String>,
}

impl S3Store {
    pub async fn new(config: &StorageConfig) -> anyhow::Result<Self> {
        // Standard AWS credential chain: env vars locally, the ECS task role in AWS.
        // No long-lived access keys are configured anywhere in production.
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .load()
            .await;

        let build = |endpoint: Option<&String>| {
            let mut builder = aws_sdk_s3::config::Builder::from(&shared)
                .force_path_style(config.force_path_style)
                // Only add checksums where the operation requires them or we set one explicitly.
                // Otherwise the SDK would sign a default CRC32 of an *empty* body into presigned
                // PUT URLs, which then fails for every real upload.
                .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
                .response_checksum_validation(ResponseChecksumValidation::WhenRequired);
            if let Some(endpoint) = endpoint {
                builder = builder.endpoint_url(endpoint);
            }
            Client::from_conf(builder.build())
        };

        let client = build(config.endpoint_url.as_ref());
        let presign_client = build(
            config
                .public_endpoint_url
                .as_ref()
                .or(config.endpoint_url.as_ref()),
        );

        Ok(Self {
            client,
            presign_client,
            bucket: config.bucket.clone(),
            sse_kms_key_id: config.sse_kms_key_id.clone(),
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Create the bucket if it does not exist. Only used by local tooling and tests;
    /// in AWS the bucket is created (with its policies) by Terraform.
    pub async fn ensure_bucket(&self) -> anyhow::Result<()> {
        if self
            .client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .is_ok()
        {
            return Ok(());
        }
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(err)
                if err.as_service_error().is_some_and(|e| {
                    e.is_bucket_already_owned_by_you() || e.is_bucket_already_exists()
                }) =>
            {
                Ok(())
            }
            Err(err) => Err(err).context("create_bucket failed"),
        }
    }

    fn sse(&self) -> (Option<ServerSideEncryption>, Option<String>) {
        match &self.sse_kms_key_id {
            Some(key) => (Some(ServerSideEncryption::AwsKms), Some(key.clone())),
            None => (None, None),
        }
    }
}

fn presigning_config(ttl: Duration) -> anyhow::Result<PresigningConfig> {
    PresigningConfig::expires_in(ttl).context("invalid presigned URL TTL")
}

fn to_presigned(req: aws_sdk_s3::presigning::PresignedRequest, ttl: Duration) -> PresignedRequest {
    PresignedRequest {
        method: req.method().to_string(),
        url: req.uri().to_string(),
        headers: req
            .headers()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
        expires_at: Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_default(),
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    async fn presign_put(
        &self,
        spec: PutObjectSpec<'_>,
        ttl: Duration,
    ) -> anyhow::Result<PresignedRequest> {
        let (sse, kms_key) = self.sse();
        let size = i64::try_from(spec.size).context("object too large")?;
        // Everything set here becomes a *signed* header. The client must send exactly these
        // values, so S3 enforces them for us:
        //  * Content-Length: the declared size; a bigger or smaller body is rejected.
        //  * x-amz-checksum-sha256: S3 hashes the body and rejects it (BadDigest) on mismatch.
        //  * Content-Type and SSE settings: the client cannot change them.
        let req = self
            .presign_client
            .put_object()
            .bucket(&self.bucket)
            .key(spec.key)
            .content_length(size)
            .content_type(spec.content_type)
            .checksum_sha256(spec.sha256_b64)
            .set_server_side_encryption(sse)
            .set_ssekms_key_id(kms_key)
            .presigned(presigning_config(ttl)?)
            .await
            .context("presign PutObject")?;
        Ok(to_presigned(req, ttl))
    }

    async fn presign_get(
        &self,
        spec: GetObjectSpec<'_>,
        ttl: Duration,
    ) -> anyhow::Result<PresignedRequest> {
        let req = self
            .presign_client
            .get_object()
            .bucket(&self.bucket)
            .key(spec.key)
            // Response header overrides are part of the signature, so the client cannot remove
            // them. `attachment` stops browsers from rendering uploaded HTML/SVG inline from
            // the bucket's origin (stored XSS).
            .response_content_disposition(content_disposition(spec.download_filename))
            .response_content_type(spec.content_type)
            .presigned(presigning_config(ttl)?)
            .await
            .context("presign GetObject")?;
        Ok(to_presigned(req, ttl))
    }

    async fn head(&self, key: &str) -> anyhow::Result<Option<ObjectInfo>> {
        let result = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await;
        match result {
            Ok(out) => Ok(Some(ObjectInfo {
                size: out
                    .content_length()
                    .and_then(|n| u64::try_from(n).ok())
                    .unwrap_or(0),
                checksum_sha256: out.checksum_sha256().map(str::to_owned),
            })),
            Err(err) if err.as_service_error().is_some_and(|e| e.is_not_found()) => Ok(None),
            Err(err) => Err(err).context("HeadObject failed"),
        }
    }

    async fn read_prefix(&self, key: &str, len: u64) -> anyhow::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(format!("bytes=0-{}", len - 1))
            .send()
            .await
            .context("ranged GetObject failed")?;
        let bytes = out
            .body
            .collect()
            .await
            .context("reading object prefix")?
            .into_bytes();
        Ok(bytes.to_vec())
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .context("DeleteObject failed")?;
        Ok(())
    }

    async fn create_multipart(&self, key: &str, content_type: &str) -> anyhow::Result<String> {
        let (sse, kms_key) = self.sse();
        let out = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            // Every part must then carry a SHA-256 that S3 verifies on arrival.
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .set_server_side_encryption(sse)
            .set_ssekms_key_id(kms_key)
            .send()
            .await
            .context("CreateMultipartUpload failed")?;
        out.upload_id()
            .map(str::to_owned)
            .context("CreateMultipartUpload returned no upload id")
    }

    async fn presign_upload_part(
        &self,
        spec: UploadPartSpec<'_>,
        ttl: Duration,
    ) -> anyhow::Result<PresignedRequest> {
        let req = self
            .presign_client
            .upload_part()
            .bucket(&self.bucket)
            .key(spec.key)
            .upload_id(spec.upload_id)
            .part_number(i32::try_from(spec.part_number).context("part number out of range")?)
            // Same idea as single PUTs: exact size and SHA-256 of *this part* are signed.
            .content_length(i64::try_from(spec.size).context("part too large")?)
            .checksum_sha256(spec.sha256_b64)
            .presigned(presigning_config(ttl)?)
            .await
            .context("presign UploadPart")?;
        Ok(to_presigned(req, ttl))
    }

    async fn list_parts(
        &self,
        key: &str,
        upload_id: &str,
    ) -> anyhow::Result<Option<Vec<UploadedPart>>> {
        let mut parts = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let result = self
                .client
                .list_parts()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(upload_id)
                .set_part_number_marker(marker.clone())
                .send()
                .await;
            let out = match result {
                Ok(out) => out,
                Err(err)
                    if err
                        .as_service_error()
                        .is_some_and(|e| e.meta().code() == Some("NoSuchUpload")) =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(err).context("ListParts failed"),
            };
            for p in out.parts() {
                parts.push(UploadedPart {
                    part_number: p
                        .part_number()
                        .and_then(|n| u32::try_from(n).ok())
                        .unwrap_or(0),
                    size: p.size().and_then(|n| u64::try_from(n).ok()).unwrap_or(0),
                    etag: p.e_tag().unwrap_or_default().to_string(),
                    checksum_sha256: p.checksum_sha256().map(str::to_owned),
                });
            }
            // ListParts returns at most 1,000 parts per page.
            if out.is_truncated() == Some(true) {
                marker = out.next_part_number_marker().map(str::to_owned);
                if marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        parts.sort_by_key(|p| p.part_number);
        Ok(Some(parts))
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> anyhow::Result<CompleteOutcome> {
        let completed: Vec<CompletedPart> = parts
            .iter()
            .map(|p| {
                CompletedPart::builder()
                    .part_number(i32::try_from(p.part_number).unwrap_or(i32::MAX))
                    .e_tag(&p.etag)
                    .set_checksum_sha256(p.checksum_sha256.clone())
                    .build()
            })
            .collect();
        let result = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(completed))
                    .build(),
            )
            .send()
            .await;
        match result {
            Ok(out) => Ok(CompleteOutcome::Completed {
                checksum_sha256: out.checksum_sha256().map(str::to_owned),
            }),
            Err(err) => {
                let code = err
                    .as_service_error()
                    .and_then(|e| e.meta().code())
                    .map(str::to_owned);
                match code.as_deref() {
                    Some(
                        "InvalidPart" | "InvalidPartOrder" | "EntityTooSmall" | "BadDigest"
                        | "InvalidRequest",
                    ) => Ok(CompleteOutcome::Rejected {
                        code: code.unwrap_or_default(),
                    }),
                    _ => Err(err).context("CompleteMultipartUpload failed"),
                }
            }
        }
    }

    async fn abort_multipart(&self, key: &str, upload_id: &str) -> anyhow::Result<()> {
        match self
            .client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_no_such_upload()) =>
            {
                Ok(())
            }
            Err(err) => Err(err).context("AbortMultipartUpload failed"),
        }
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .context("HeadBucket failed")?;
        Ok(())
    }
}

/// RFC 6266 / RFC 5987 Content-Disposition with an ASCII fallback and a UTF-8 `filename*`.
pub fn content_disposition(filename: &str) -> String {
    // attr-char from RFC 5987: ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." /
    // "^" / "_" / "`" / "|" / "~". Everything else is percent-encoded.
    const ATTR_CHAR: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'!')
        .remove(b'#')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b'-')
        .remove(b'.')
        .remove(b'^')
        .remove(b'_')
        .remove(b'`')
        .remove(b'|')
        .remove(b'~');

    let ascii_fallback: String = filename
        .chars()
        .map(|c| match c {
            ' '..='~' if c != '"' && c != '\\' => c,
            _ => '_',
        })
        .collect();
    let encoded = utf8_percent_encode(filename, ATTR_CHAR);
    format!("attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_disposition_escapes_quotes_and_unicode() {
        assert_eq!(
            content_disposition("report \"final\".pdf"),
            "attachment; filename=\"report _final_.pdf\"; filename*=UTF-8''report%20%22final%22.pdf"
        );
        assert_eq!(
            content_disposition("résumé.txt"),
            "attachment; filename=\"r_sum_.txt\"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt"
        );
    }

    #[test]
    fn content_disposition_cannot_inject_headers() {
        let cd = content_disposition("a\r\nSet-Cookie: x=1");
        assert!(!cd.contains('\r') && !cd.contains('\n'));
    }
}
