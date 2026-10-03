-- Append-only security audit trail.
--
-- No foreign keys on purpose: audit records must outlive the users and files they mention.
-- In production the application's DB role should have INSERT/SELECT only on this table
-- (no UPDATE/DELETE); see docs/threat-model.md.

CREATE TABLE audit_events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id    UUID,
    action      TEXT        NOT NULL,
    outcome     TEXT        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    target_type TEXT,
    target_id   UUID,
    client_ip   TEXT,
    user_agent  TEXT,
    request_id  TEXT,
    metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, occurred_at DESC);
CREATE INDEX audit_events_target_idx ON audit_events (target_id, occurred_at DESC);
CREATE INDEX audit_events_action_idx ON audit_events (action, occurred_at DESC);
