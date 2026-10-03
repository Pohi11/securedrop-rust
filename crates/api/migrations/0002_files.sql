-- File metadata. The bytes live in S3; this table is the source of truth for ownership,
-- lifecycle state and integrity metadata.

CREATE TABLE files (
    id                UUID PRIMARY KEY,
    owner_id          UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Display name only. Never used to build the S3 key or any filesystem path.
    filename          TEXT        NOT NULL CHECK (length(filename) BETWEEN 1 AND 255),
    content_type      TEXT        NOT NULL,
    size_bytes        BIGINT      NOT NULL CHECK (size_bytes > 0),
    -- SHA-256 of the whole file as declared by the uploader (raw 32 bytes).
    sha256            BYTEA       NOT NULL CHECK (octet_length(sha256) = 32),
    -- u/{owner_id}/{file_id}: server-generated, so users cannot choose or collide keys.
    object_key        TEXT        NOT NULL UNIQUE,
    status            TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'available', 'failed', 'deleted')),
    upload_kind       TEXT        NOT NULL CHECK (upload_kind IN ('single', 'multipart')),
    s3_upload_id      TEXT,       -- multipart upload id (multipart only)
    part_size         BIGINT      CHECK (part_size > 0),
    part_count        INTEGER     CHECK (part_count BETWEEN 1 AND 10000),
    -- Checksum S3 reported after completion (full or composite "<b64>-<parts>").
    s3_checksum       TEXT,
    upload_expires_at TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at      TIMESTAMPTZ,
    deleted_at        TIMESTAMPTZ,
    -- Set once the object has actually been removed from S3 after deletion/failure.
    purged_at         TIMESTAMPTZ,

    CONSTRAINT multipart_fields CHECK (
        (upload_kind = 'single' AND s3_upload_id IS NULL AND part_size IS NULL AND part_count IS NULL)
        OR (upload_kind = 'multipart' AND s3_upload_id IS NOT NULL AND part_size IS NOT NULL AND part_count IS NOT NULL)
    )
);

CREATE INDEX files_owner_status_idx ON files (owner_id, status, created_at DESC);
-- Partial indexes keep the cleanup worker's scans cheap no matter how many files exist.
CREATE INDEX files_pending_expiry_idx ON files (upload_expires_at) WHERE status = 'pending';
CREATE INDEX files_unpurged_idx ON files (updated_at) WHERE status IN ('deleted', 'failed') AND purged_at IS NULL;

-- Per-part SHA-256 checksums the client declared when it asked for presigned part URLs.
-- On completion, S3's own per-part checksums must match these exactly.
CREATE TABLE upload_parts (
    file_id     UUID    NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    sha256      BYTEA   NOT NULL CHECK (octet_length(sha256) = 32),
    size_bytes  BIGINT  NOT NULL CHECK (size_bytes > 0),
    PRIMARY KEY (file_id, part_number)
);
