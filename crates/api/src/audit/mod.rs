//! Security audit trail.
//!
//! Every security-relevant action (login, failed login, token reuse, upload, download, share,
//! revoke, delete) is written to `audit_events` and also emitted as a structured log line
//! (target `audit`), so it shows up both in SQL and in CloudWatch Logs.

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::client_meta::ClientMeta;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

#[must_use = "call .record() to persist the audit event"]
pub struct AuditEvent {
    action: &'static str,
    outcome: Outcome,
    actor_id: Option<Uuid>,
    target: Option<(&'static str, Uuid)>,
    metadata: Value,
}

impl AuditEvent {
    pub fn new(action: &'static str, outcome: Outcome) -> Self {
        Self {
            action,
            outcome,
            actor_id: None,
            target: None,
            metadata: Value::Object(Default::default()),
        }
    }

    pub fn actor(mut self, actor_id: Uuid) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    pub fn target(mut self, kind: &'static str, id: Uuid) -> Self {
        self.target = Some((kind, id));
        self
    }

    pub fn metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Persist the event. Audit failures are logged loudly but do not fail the user's request:
    /// we chose availability here. A stricter system (e.g. regulated data) might fail closed.
    pub async fn record(self, db: &PgPool, client: &ClientMeta) {
        let (target_type, target_id) = self
            .target
            .map_or((None, None), |(kind, id)| (Some(kind), Some(id)));

        tracing::info!(
            target: "audit",
            action = self.action,
            outcome = self.outcome.as_str(),
            actor_id = self.actor_id.as_ref().map(tracing::field::display),
            target_type,
            target_id = target_id.as_ref().map(tracing::field::display),
            client_ip = client.ip.as_deref(),
            request_id = client.request_id.as_deref(),
            metadata = %self.metadata,
            "audit event"
        );

        let result = sqlx::query!(
            r#"INSERT INTO audit_events
                 (actor_id, action, outcome, target_type, target_id, client_ip, user_agent, request_id, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
            self.actor_id,
            self.action,
            self.outcome.as_str(),
            target_type,
            target_id,
            client.ip.as_deref(),
            client.user_agent.as_deref(),
            client.request_id.as_deref(),
            self.metadata
        )
        .execute(db)
        .await;

        if let Err(err) = result {
            tracing::error!(%err, action = self.action, "failed to write audit event");
        }
    }
}
