use chrono::{DateTime, Utc};
use securedrop_common::{FileResponse, FileStatus};
use uuid::Uuid;

/// A row of the `files` table.
#[derive(Debug, Clone)]
pub struct FileRecord {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub sha256: Vec<u8>,
    pub object_key: String,
    pub status: String,
    pub upload_kind: String,
    pub s3_upload_id: Option<String>,
    pub part_size: Option<i64>,
    pub part_count: Option<i32>,
    pub s3_checksum: Option<String>,
    pub upload_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_AVAILABLE: &str = "available";
pub const KIND_SINGLE: &str = "single";
pub const KIND_MULTIPART: &str = "multipart";

impl FileRecord {
    pub fn status(&self) -> FileStatus {
        match self.status.as_str() {
            "pending" => FileStatus::Pending,
            "available" => FileStatus::Available,
            "failed" => FileStatus::Failed,
            _ => FileStatus::Deleted,
        }
    }

    pub fn size(&self) -> u64 {
        u64::try_from(self.size_bytes).unwrap_or(0)
    }

    pub fn to_response(&self) -> FileResponse {
        FileResponse {
            id: self.id,
            owner_id: self.owner_id,
            filename: self.filename.clone(),
            content_type: self.content_type.clone(),
            size_bytes: self.size(),
            sha256: hex::encode(&self.sha256),
            status: self.status(),
            created_at: self.created_at,
            completed_at: self.completed_at,
        }
    }
}

/// `u/{owner}/{file}`. Server-generated: users never influence object keys.
pub fn object_key(owner_id: Uuid, file_id: Uuid) -> String {
    format!("u/{owner_id}/{file_id}")
}
