use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub storage_quota_bytes: i64,
    pub failed_login_count: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn is_locked(&self, now: DateTime<Utc>) -> bool {
        self.locked_until.is_some_and(|until| until > now)
    }
}

/// Normalise and validate an email address.
///
/// We deliberately do not try to implement RFC 5322 (nobody's validator agrees with it anyway).
/// The goals are: one canonical form per mailbox (so `Alice@X.com` and `alice@x.com` cannot be
/// two accounts), and rejecting obvious garbage, whitespace and control characters.
pub fn normalize_email(raw: &str) -> AppResult<String> {
    let email = raw.trim().to_lowercase();
    let invalid = || AppError::validation("email address is invalid");

    if !(3..=254).contains(&email.len())
        || email.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid());
    }
    let (local, domain) = email.split_once('@').ok_or_else(invalid)?;
    if local.is_empty()
        || local.len() > 64
        || domain.contains('@')
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return Err(invalid());
    }
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_whitespace() {
        assert_eq!(
            normalize_email("  Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "a",
            "no-at-sign.com",
            "@example.com",
            "a@b",
            "a@@b.com",
            "a b@c.com",
            "a@.com",
            "a@b..com",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
