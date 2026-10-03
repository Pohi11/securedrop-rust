//! Object storage abstraction.
//!
//! Business logic talks to the [`ObjectStore`] trait, never to the AWS SDK directly. That keeps
//! S3 details (SDK error types, header names) in one file, and makes it possible to swap the
//! backend or use a fake in unit tests.
//!
//! Note what is *not* here: there is no `put_object(bytes)` or `get_object() -> bytes`. The API
//! never moves file contents. It only signs requests that clients execute against S3.

pub mod s3;

use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub use s3::S3Store;

/// A signed request for the client to execute directly against the object store.
#[derive(Clone)]
pub struct PresignedRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub expires_at: DateTime<Utc>,
}

impl From<PresignedRequest> for securedrop_common::PresignedRequest {
    fn from(p: PresignedRequest) -> Self {
        Self {
            method: p.method,
            url: p.url,
            headers: p.headers,
            expires_at: p.expires_at,
        }
    }
}

pub struct PutObjectSpec<'a> {
    pub key: &'a str,
    pub size: u64,
    /// Base64 SHA-256 (the format S3 uses in `x-amz-checksum-sha256`).
    pub sha256_b64: &'a str,
    pub content_type: &'a str,
}

pub struct GetObjectSpec<'a> {
    pub key: &'a str,
    /// Forced into the response as `Content-Disposition: attachment; filename=...`.
    pub download_filename: &'a str,
    pub content_type: &'a str,
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub size: u64,
    /// The checksum S3 computed and verified on upload (base64; "<b64>-<n>" for multipart).
    pub checksum_sha256: Option<String>,
}

#[async_trait]
pub trait ObjectStore: Send + Sync + 'static {
    async fn presign_put(
        &self,
        spec: PutObjectSpec<'_>,
        ttl: Duration,
    ) -> anyhow::Result<PresignedRequest>;
    async fn presign_get(
        &self,
        spec: GetObjectSpec<'_>,
        ttl: Duration,
    ) -> anyhow::Result<PresignedRequest>;
    /// Object metadata, or `None` if the object does not exist.
    async fn head(&self, key: &str) -> anyhow::Result<Option<ObjectInfo>>;
    /// Read the first `len` bytes (a ranged GET), for content sniffing without downloading the file.
    async fn read_prefix(&self, key: &str, len: u64) -> anyhow::Result<Vec<u8>>;
    /// Delete an object. Deleting a missing object is not an error (S3 semantics).
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
    /// Cheap connectivity check for readiness probes.
    async fn health_check(&self) -> anyhow::Result<()>;
}
