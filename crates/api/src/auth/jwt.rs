//! Access tokens: short-lived, signed JWTs (HS256).
//!
//! The access token is a *bearer* credential checked on every request without a database
//! lookup, which is why it must be short-lived (15 minutes by default). Revocation before
//! expiry is handled by the session denylist in [`super::revocation`].

use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::AuthConfig,
    error::{AppError, AppResult},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Subject: the user id.
    pub sub: Uuid,
    /// Session id = the refresh-token family this access token was minted from. Revoking the
    /// session (logout, refresh-token reuse) invalidates every access token carrying this sid.
    pub sid: Uuid,
    /// Unique token id, recorded in audit logs.
    pub jti: Uuid,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub aud: String,
}

#[derive(Clone)]
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    issuer: String,
    audience: String,
    ttl: Duration,
}

impl JwtKeys {
    pub fn new(config: &AuthConfig) -> Self {
        let secret = config.jwt_secret.expose_secret().as_bytes();

        // Pin the algorithm. Never trust the `alg` header of an incoming token: accepting
        // `none`, or verifying an RS256 public key as an HMAC secret, are classic JWT bypasses.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&config.jwt_issuer]);
        validation.set_audience(&[&config.jwt_audience]);
        validation.set_required_spec_claims(&["exp", "nbf", "iat", "sub", "iss", "aud"]);
        validation.validate_nbf = true;
        // Small clock-skew allowance between API replicas.
        validation.leeway = 5;

        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            validation,
            issuer: config.jwt_issuer.clone(),
            audience: config.jwt_audience.clone(),
            ttl: config.access_token_ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn issue(&self, user_id: Uuid, session_id: Uuid) -> AppResult<(String, Claims)> {
        let now = Utc::now().timestamp();
        let ttl = i64::try_from(self.ttl.as_secs()).map_err(AppError::internal)?;
        let claims = Claims {
            sub: user_id,
            sid: session_id,
            jti: Uuid::new_v4(),
            iat: now,
            nbf: now,
            exp: now + ttl,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
        };
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(AppError::internal)?;
        Ok((token, claims))
    }

    /// Verify signature, algorithm, issuer, audience, `exp` and `nbf`.
    /// Any failure is reported uniformly as `Unauthorized`; the reason is only logged.
    pub fn verify(&self, token: &str) -> AppResult<Claims> {
        decode::<Claims>(token, &self.decoding, &self.validation)
            .map(|data| data.claims)
            .map_err(|err| {
                tracing::debug!(error = %err, "rejected access token");
                AppError::Unauthorized
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(secret: &str) -> AuthConfig {
        AuthConfig {
            jwt_secret: secret.into(),
            jwt_issuer: "securedrop".into(),
            jwt_audience: "securedrop-api".into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(3600),
            max_failed_logins: 5,
            lockout_duration: Duration::from_secs(60),
        }
    }

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn roundtrip() {
        let keys = JwtKeys::new(&config(SECRET));
        let (user, session) = (Uuid::now_v7(), Uuid::now_v7());
        let (token, claims) = keys.issue(user, session).unwrap();
        let verified = keys.verify(&token).unwrap();
        assert_eq!(verified, claims);
        assert_eq!(verified.sub, user);
        assert_eq!(verified.sid, session);
    }

    #[test]
    fn rejects_wrong_secret() {
        let (token, _) = JwtKeys::new(&config(SECRET))
            .issue(Uuid::now_v7(), Uuid::now_v7())
            .unwrap();
        let other = JwtKeys::new(&config("ffffffffffffffffffffffffffffffff"));
        assert!(other.verify(&token).is_err());
    }

    #[test]
    fn rejects_wrong_audience() {
        let (token, _) = JwtKeys::new(&config(SECRET))
            .issue(Uuid::now_v7(), Uuid::now_v7())
            .unwrap();
        let mut cfg = config(SECRET);
        cfg.jwt_audience = "some-other-service".into();
        assert!(JwtKeys::new(&cfg).verify(&token).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let keys = JwtKeys::new(&config(SECRET));
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: Uuid::now_v7(),
            sid: Uuid::now_v7(),
            jti: Uuid::new_v4(),
            iat: now - 3600,
            nbf: now - 3600,
            exp: now - 60,
            iss: "securedrop".into(),
            aud: "securedrop-api".into(),
        };
        let token = encode(&Header::new(Algorithm::HS256), &claims, &keys.encoding).unwrap();
        assert!(keys.verify(&token).is_err());
    }

    #[test]
    fn rejects_alg_none_and_tampered_payload() {
        let keys = JwtKeys::new(&config(SECRET));
        let (token, _) = keys.issue(Uuid::now_v7(), Uuid::now_v7()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();

        // Header {"alg":"none","typ":"JWT"} with the signature stripped.
        let none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
        let unsigned = format!("{none_header}.{}.", parts[1]);
        assert!(keys.verify(&unsigned).is_err());

        // Swap in a different (validly encoded) payload but keep the old signature.
        let (other, _) = keys.issue(Uuid::now_v7(), Uuid::now_v7()).unwrap();
        let other_payload = other.split('.').nth(1).unwrap().to_string();
        parts[1] = &other_payload;
        assert!(keys.verify(&parts.join(".")).is_err());
    }
}
