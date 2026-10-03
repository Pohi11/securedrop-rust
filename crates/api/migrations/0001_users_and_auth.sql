-- Users and authentication state.
--
-- Emails are normalised (trimmed + lowercased) by the application before they reach the
-- database, and the CHECK constraint makes that invariant impossible to violate by accident.

CREATE TABLE users (
    id                  UUID PRIMARY KEY,
    email               TEXT        NOT NULL UNIQUE
                                    CHECK (email = lower(btrim(email)) AND length(email) BETWEEN 3 AND 254),
    -- PHC string, e.g. $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>. Never a plaintext password.
    password_hash       TEXT        NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    storage_quota_bytes BIGINT      NOT NULL CHECK (storage_quota_bytes >= 0),
    failed_login_count  INTEGER     NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Opaque refresh tokens. Only a SHA-256 of the token is stored: a database leak does not
-- hand the attacker usable tokens. (A fast hash is fine here because the token is 256 bits
-- of randomness, unlike a password, so there is nothing to brute-force.)
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- All tokens descended from one login share a family. Reuse of any rotated token
    -- revokes the whole family (OAuth 2.0 Security BCP, refresh token rotation).
    family_id   UUID        NOT NULL,
    token_hash  BYTEA       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at     TIMESTAMPTZ,          -- set when this token is exchanged (rotated)
    revoked_at  TIMESTAMPTZ,          -- set on logout or reuse detection
    user_agent  TEXT,
    client_ip   TEXT
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_active_idx ON refresh_tokens (user_id) WHERE revoked_at IS NULL;
