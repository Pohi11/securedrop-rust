-- Sharing: direct grants to other users, and bearer share links.

CREATE TABLE file_grants (
    file_id    UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    grantee_id UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    granted_by UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, grantee_id),
    CHECK (grantee_id <> granted_by)
);

CREATE INDEX file_grants_grantee_idx ON file_grants (grantee_id);

CREATE TABLE share_links (
    id             UUID PRIMARY KEY,
    file_id        UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    created_by     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the bearer token; the token itself is shown to the creator exactly once.
    token_hash     BYTEA       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at     TIMESTAMPTZ NOT NULL,
    max_downloads  INTEGER     CHECK (max_downloads > 0),
    download_count INTEGER     NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    revoked_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (max_downloads IS NULL OR download_count <= max_downloads)
);

CREATE INDEX share_links_file_idx ON share_links (file_id);
