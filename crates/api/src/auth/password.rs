//! Password hashing (Argon2id) and password policy.

use std::sync::{Arc, OnceLock};

use anyhow::anyhow;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher as _, PasswordVerifier as _, phc::PasswordHash},
};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Semaphore;

use crate::error::{AppError, AppResult};

/// OWASP Password Storage Cheat Sheet minimum for Argon2id: m = 19 MiB, t = 2, p = 1.
const M_COST_KIB: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

pub const MIN_PASSWORD_CHARS: usize = 12;
/// Upper bound so a 10 MB "password" cannot be used to burn CPU.
pub const MAX_PASSWORD_CHARS: usize = 128;

/// Argon2id hasher with bounded concurrency.
///
/// Each hash allocates ~19 MiB and takes tens of milliseconds of CPU. Without a limit, a burst
/// of 500 login attempts would try to allocate ~10 GB at once: an easy denial of service. The
/// semaphore caps simultaneous hashes; excess requests wait (and the request timeout bounds
/// how long they wait).
#[derive(Clone)]
pub struct PasswordHasher {
    argon2: Arc<Argon2<'static>>,
    permits: Arc<Semaphore>,
}

impl PasswordHasher {
    pub fn new(max_concurrent: usize) -> anyhow::Result<Self> {
        Ok(Self {
            argon2: Arc::new(argon2_instance()?),
            permits: Arc::new(Semaphore::new(max_concurrent.max(1))),
        })
    }

    /// Hash a password into a PHC string (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`).
    /// A fresh 128-bit random salt is generated per call.
    pub async fn hash(&self, password: &SecretString) -> AppResult<String> {
        let _permit = self.permits.acquire().await.map_err(AppError::internal)?;
        let argon2 = self.argon2.clone();
        let password = password.clone();
        // CPU-heavy work must not run on the async executor threads, or it would stall every
        // other request scheduled on that thread.
        tokio::task::spawn_blocking(move || {
            argon2
                .hash_password(password.expose_secret().as_bytes())
                .map(|h| h.to_string())
                .map_err(|e| anyhow!("argon2 hashing failed: {e}"))
        })
        .await
        .map_err(AppError::internal)?
        .map_err(AppError::Internal)
    }

    /// Verify a password against a stored PHC string. Returns `Ok(false)` on mismatch.
    ///
    /// The parameters (m, t, p, salt) are read from the PHC string itself, so hashes created
    /// with older parameters keep verifying after we raise the cost.
    pub async fn verify(&self, password: &SecretString, phc: &str) -> AppResult<bool> {
        let _permit = self.permits.acquire().await.map_err(AppError::internal)?;
        let argon2 = self.argon2.clone();
        let password = password.clone();
        let phc = phc.to_owned();
        tokio::task::spawn_blocking(move || {
            let parsed =
                PasswordHash::new(&phc).map_err(|e| anyhow!("stored hash is invalid: {e}"))?;
            match argon2.verify_password(password.expose_secret().as_bytes(), &parsed) {
                Ok(()) => Ok(true),
                Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
                Err(e) => Err(anyhow!("argon2 verification failed: {e}")),
            }
        })
        .await
        .map_err(AppError::internal)?
        .map_err(AppError::Internal)
    }

    /// Spend the same time as a real verification when the user does not exist, so response
    /// timing does not reveal which email addresses are registered.
    pub async fn verify_dummy(&self, password: &SecretString) -> AppResult<()> {
        let dummy = dummy_hash()?;
        let _ = self.verify(password, dummy).await?;
        Ok(())
    }
}

fn argon2_instance() -> anyhow::Result<Argon2<'static>> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, None)
        .map_err(|e| anyhow!("invalid argon2 params: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// A real Argon2id hash of a random value, computed once, used by [`PasswordHasher::verify_dummy`].
fn dummy_hash() -> AppResult<&'static str> {
    static DUMMY: OnceLock<String> = OnceLock::new();
    if let Some(hash) = DUMMY.get() {
        return Ok(hash);
    }
    let hash = argon2_instance()?
        .hash_password(uuid::Uuid::new_v4().as_bytes())
        .map_err(|e| anyhow!("argon2 hashing failed: {e}"))?
        .to_string();
    Ok(DUMMY.get_or_init(|| hash))
}

/// Password policy, following NIST SP 800-63B: length matters more than composition rules,
/// so we require 12+ characters and reject guessable passwords using zxcvbn (which knows
/// common passwords, keyboard patterns, dates, l33t-speak and the user's own email).
/// No "must contain a symbol" rules: they produce `Password1!`, not strong passwords.
pub fn validate_password_policy(password: &str, email: &str) -> AppResult<()> {
    let chars = password.chars().count();
    if chars < MIN_PASSWORD_CHARS {
        return Err(AppError::validation(format!(
            "password must be at least {MIN_PASSWORD_CHARS} characters"
        )));
    }
    if chars > MAX_PASSWORD_CHARS {
        return Err(AppError::validation(format!(
            "password must be at most {MAX_PASSWORD_CHARS} characters"
        )));
    }

    let local_part = email.split('@').next().unwrap_or_default();
    let estimate = zxcvbn::zxcvbn(password, &[email, local_part, "securedrop"]);
    if u8::from(estimate.score()) < 3 {
        let hint = estimate
            .feedback()
            .and_then(|f| f.warning().map(|w| w.to_string()))
            .unwrap_or_else(|| "choose a longer, less predictable password".into());
        return Err(AppError::validation(format!(
            "password is too weak: {hint}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_and_verify_roundtrip() {
        let hasher = PasswordHasher::new(2).unwrap();
        let pw = SecretString::from("correct horse battery staple 42");
        let phc = hasher.hash(&pw).await.unwrap();

        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(hasher.verify(&pw, &phc).await.unwrap());
        assert!(
            !hasher
                .verify(&SecretString::from("wrong password"), &phc)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn same_password_gets_different_salts() {
        let hasher = PasswordHasher::new(2).unwrap();
        let pw = SecretString::from("correct horse battery staple 42");
        assert_ne!(
            hasher.hash(&pw).await.unwrap(),
            hasher.hash(&pw).await.unwrap()
        );
    }

    #[test]
    fn policy_rejects_short_common_and_email_based_passwords() {
        let email = "jonathan@example.com";
        assert!(validate_password_policy("short", email).is_err());
        assert!(validate_password_policy("password1234", email).is_err());
        assert!(validate_password_policy("jonathan1234", email).is_err());
        assert!(validate_password_policy(&"a".repeat(129), email).is_err());
        assert!(validate_password_policy("violet-tractor-mango-91", email).is_ok());
    }
}
