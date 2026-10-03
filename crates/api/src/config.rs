//! Application configuration, loaded from environment variables.
//!
//! Every setting has a single source of truth (an env var) so the same binary
//! runs locally (values from `.env`), in CI (service containers) and on ECS
//! (values injected from Secrets Manager / task definition). Secrets are wrapped
//! in [`SecretString`] so they cannot be accidentally logged via `Debug`.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{Context, bail};
use secrecy::{ExposeSecret, SecretString};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// S3 hard limits that our own configuration must respect.
pub const S3_MIN_PART_SIZE: u64 = 5 * MIB;
pub const S3_MAX_PART_SIZE: u64 = 5 * GIB;
pub const S3_MAX_PARTS: u64 = 10_000;
pub const S3_MAX_SINGLE_PUT: u64 = 5 * GIB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Local,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub environment: Environment,
    pub http: HttpConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub uploads: UploadPolicy,
    pub rate_limit: RateLimitConfig,
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub bind_addr: SocketAddr,
    /// Separate listener for `/metrics`, so it is never exposed through the public load balancer.
    pub metrics_addr: SocketAddr,
    pub cors_allowed_origins: Vec<String>,
    pub request_timeout: Duration,
    /// Only trust `X-Forwarded-For` when running behind a known proxy (the ALB).
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: SecretString,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: SecretString,
    /// Prefix applied to every key, so several environments (or test runs) can share one Redis.
    pub key_prefix: String,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: SecretString,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub max_failed_logins: i32,
    pub lockout_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub bucket: String,
    pub region: String,
    /// Endpoint the API uses to talk to S3 (unset in AWS; set for local S3-compatible stores).
    pub endpoint_url: Option<String>,
    /// Endpoint embedded in presigned URLs handed to clients. In Docker the API reaches the
    /// store as `http://s3:9000` but the user's machine reaches it as `http://localhost:59000`,
    /// and the host is part of the SigV4 signature, so the two must be configurable separately.
    pub public_endpoint_url: Option<String>,
    pub force_path_style: bool,
    pub upload_url_ttl: Duration,
    pub download_url_ttl: Duration,
    pub share_download_url_ttl: Duration,
    /// When set, objects are written with SSE-KMS using this key (in AWS the bucket default
    /// encryption already enforces this; setting it here makes it explicit in each request).
    pub sse_kms_key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UploadPolicy {
    pub max_file_size: u64,
    /// Files up to this size use one presigned PUT; larger files use multipart.
    pub single_part_max: u64,
    pub part_size: u64,
    pub default_user_quota: u64,
    /// Pending uploads not completed within this window are aborted by the cleanup worker.
    pub pending_upload_ttl: Duration,
    pub allowed_content_types: Vec<String>,
    pub cleanup_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Requests per minute per client IP on `/auth/*`.
    pub auth_per_minute: u32,
    pub auth_burst: u32,
    /// Requests per minute per authenticated user (or IP for anonymous) everywhere else.
    pub api_per_minute: u32,
    pub api_burst: u32,
}

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub log_format: LogFormat,
    pub log_filter: String,
}

impl Config {
    /// Load configuration from the process environment (and `.env`, if present).
    pub fn from_env() -> anyhow::Result<Self> {
        // A missing .env file is normal in production; any other error is not.
        if let Err(err) = dotenvy::dotenv()
            && !err.not_found()
        {
            return Err(err).context("failed to read .env file");
        }

        let environment = match optional("APP_ENV").as_deref() {
            None | Some("local") => Environment::Local,
            Some("production") => Environment::Production,
            Some(other) => bail!("APP_ENV must be 'local' or 'production', got '{other}'"),
        };

        let config = Config {
            environment,
            http: HttpConfig {
                bind_addr: parse_or("BIND_ADDR", "0.0.0.0:8080".parse()?)?,
                metrics_addr: parse_or("METRICS_ADDR", "0.0.0.0:9100".parse()?)?,
                cors_allowed_origins: list_or("CORS_ALLOWED_ORIGINS", &[]),
                request_timeout: secs_or("REQUEST_TIMEOUT_SECS", 15)?,
                trust_proxy_headers: parse_or("TRUST_PROXY_HEADERS", false)?,
            },
            database: DatabaseConfig {
                url: secret("DATABASE_URL")?,
                max_connections: parse_or("DATABASE_MAX_CONNECTIONS", 10)?,
            },
            redis: RedisConfig {
                url: secret("REDIS_URL")?,
                key_prefix: optional("REDIS_KEY_PREFIX").unwrap_or_else(|| "securedrop:".into()),
            },
            auth: AuthConfig {
                jwt_secret: secret("JWT_SECRET")?,
                jwt_issuer: optional("JWT_ISSUER").unwrap_or_else(|| "securedrop".into()),
                jwt_audience: optional("JWT_AUDIENCE").unwrap_or_else(|| "securedrop-api".into()),
                access_token_ttl: secs_or("ACCESS_TOKEN_TTL_SECS", 15 * 60)?,
                refresh_token_ttl: secs_or("REFRESH_TOKEN_TTL_SECS", 14 * 24 * 60 * 60)?,
                max_failed_logins: parse_or("MAX_FAILED_LOGINS", 10)?,
                lockout_duration: secs_or("LOCKOUT_SECS", 15 * 60)?,
            },
            storage: StorageConfig {
                bucket: required("S3_BUCKET")?,
                region: optional("AWS_REGION").unwrap_or_else(|| "us-east-1".into()),
                endpoint_url: optional("S3_ENDPOINT_URL"),
                public_endpoint_url: optional("S3_PUBLIC_ENDPOINT_URL"),
                force_path_style: parse_or("S3_FORCE_PATH_STYLE", false)?,
                upload_url_ttl: secs_or("UPLOAD_URL_TTL_SECS", 15 * 60)?,
                download_url_ttl: secs_or("DOWNLOAD_URL_TTL_SECS", 5 * 60)?,
                share_download_url_ttl: secs_or("SHARE_DOWNLOAD_URL_TTL_SECS", 60)?,
                sse_kms_key_id: optional("S3_SSE_KMS_KEY_ID"),
            },
            uploads: UploadPolicy {
                max_file_size: parse_or("MAX_FILE_SIZE_BYTES", 5 * GIB)?,
                single_part_max: parse_or("SINGLE_PART_MAX_BYTES", 64 * MIB)?,
                part_size: parse_or("MULTIPART_PART_SIZE_BYTES", 16 * MIB)?,
                default_user_quota: parse_or("DEFAULT_USER_QUOTA_BYTES", 10 * GIB)?,
                pending_upload_ttl: secs_or("PENDING_UPLOAD_TTL_SECS", 24 * 60 * 60)?,
                allowed_content_types: list_or("ALLOWED_CONTENT_TYPES", DEFAULT_CONTENT_TYPES),
                cleanup_interval: secs_or("CLEANUP_INTERVAL_SECS", 5 * 60)?,
            },
            rate_limit: RateLimitConfig {
                enabled: parse_or("RATE_LIMIT_ENABLED", true)?,
                auth_per_minute: parse_or("RATE_LIMIT_AUTH_PER_MINUTE", 10)?,
                auth_burst: parse_or("RATE_LIMIT_AUTH_BURST", 5)?,
                api_per_minute: parse_or("RATE_LIMIT_API_PER_MINUTE", 300)?,
                api_burst: parse_or("RATE_LIMIT_API_BURST", 60)?,
            },
            telemetry: TelemetryConfig {
                log_format: match optional("LOG_FORMAT").as_deref() {
                    Some("json") => LogFormat::Json,
                    Some("pretty") => LogFormat::Pretty,
                    None if environment == Environment::Production => LogFormat::Json,
                    None => LogFormat::Pretty,
                    Some(other) => bail!("LOG_FORMAT must be 'json' or 'pretty', got '{other}'"),
                },
                log_filter: optional("RUST_LOG")
                    .unwrap_or_else(|| "info,securedrop_api=debug,tower_http=info".into()),
            },
        };

        config.validate()?;
        Ok(config)
    }

    /// Fail fast at startup on settings that would be insecure or that S3 would reject later.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.auth.jwt_secret.expose_secret().len() < 32 {
            bail!("JWT_SECRET must be at least 32 bytes (256 bits) for HS256");
        }
        if self.auth.access_token_ttl > Duration::from_secs(60 * 60) {
            bail!("ACCESS_TOKEN_TTL_SECS should not exceed one hour");
        }
        let u = &self.uploads;
        if !(S3_MIN_PART_SIZE..=S3_MAX_PART_SIZE).contains(&u.part_size) {
            bail!("MULTIPART_PART_SIZE_BYTES must be between 5 MiB and 5 GiB");
        }
        if u.single_part_max > S3_MAX_SINGLE_PUT {
            bail!("SINGLE_PART_MAX_BYTES cannot exceed the 5 GiB S3 single PUT limit");
        }
        if u.max_file_size.div_ceil(u.part_size) > S3_MAX_PARTS {
            bail!("MAX_FILE_SIZE_BYTES / part size would exceed S3's 10,000 part limit");
        }
        // Presigned URLs signed with temporary (role) credentials stop working when those
        // credentials expire, and SigV4 caps presigned URLs at 7 days regardless.
        for ttl in [
            self.storage.upload_url_ttl,
            self.storage.download_url_ttl,
            self.storage.share_download_url_ttl,
        ] {
            if ttl.is_zero() || ttl > Duration::from_secs(60 * 60) {
                bail!("presigned URL TTLs must be between 1 second and 1 hour");
            }
        }
        if self.environment == Environment::Production {
            if self.storage.endpoint_url.is_some() {
                bail!("S3_ENDPOINT_URL must not be set in production (use real S3)");
            }
            if self.storage.sse_kms_key_id.is_none() {
                bail!("S3_SSE_KMS_KEY_ID is required in production");
            }
            if !self.rate_limit.enabled {
                bail!("rate limiting cannot be disabled in production");
            }
        }
        Ok(())
    }
}

/// Default MIME allowlist. Deliberately excludes `text/html` and `image/svg+xml`: both can carry
/// script, and although downloads are forced to `attachment`, defence in depth is cheap here.
const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/json",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/octet-stream",
    "text/plain",
    "text/csv",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "video/mp4",
    "audio/mpeg",
];

fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn required(key: &str) -> anyhow::Result<String> {
    optional(key).with_context(|| format!("missing required environment variable {key}"))
}

fn secret(key: &str) -> anyhow::Result<SecretString> {
    required(key).map(SecretString::from)
}

fn parse_or<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match optional(key) {
        None => Ok(default),
        Some(raw) => raw
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
    }
}

fn secs_or(key: &str, default: u64) -> anyhow::Result<Duration> {
    parse_or(key, default).map(Duration::from_secs)
}

fn list_or(key: &str, default: &[&str]) -> Vec<String> {
    match optional(key) {
        Some(raw) => raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => default.iter().map(|s| s.to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            environment: Environment::Local,
            http: HttpConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                metrics_addr: "127.0.0.1:0".parse().unwrap(),
                cors_allowed_origins: vec![],
                request_timeout: Duration::from_secs(5),
                trust_proxy_headers: false,
            },
            database: DatabaseConfig {
                url: "postgres://x".into(),
                max_connections: 1,
            },
            redis: RedisConfig {
                url: "redis://x".into(),
                key_prefix: "t:".into(),
            },
            auth: AuthConfig {
                jwt_secret: "0123456789abcdef0123456789abcdef".into(),
                jwt_issuer: "i".into(),
                jwt_audience: "a".into(),
                access_token_ttl: Duration::from_secs(900),
                refresh_token_ttl: Duration::from_secs(3600),
                max_failed_logins: 5,
                lockout_duration: Duration::from_secs(60),
            },
            storage: StorageConfig {
                bucket: "b".into(),
                region: "us-east-1".into(),
                endpoint_url: None,
                public_endpoint_url: None,
                force_path_style: false,
                upload_url_ttl: Duration::from_secs(900),
                download_url_ttl: Duration::from_secs(300),
                share_download_url_ttl: Duration::from_secs(60),
                sse_kms_key_id: None,
            },
            uploads: UploadPolicy {
                max_file_size: 5 * GIB,
                single_part_max: 64 * MIB,
                part_size: 16 * MIB,
                default_user_quota: 10 * GIB,
                pending_upload_ttl: Duration::from_secs(3600),
                allowed_content_types: vec!["text/plain".into()],
                cleanup_interval: Duration::from_secs(60),
            },
            rate_limit: RateLimitConfig {
                enabled: true,
                auth_per_minute: 10,
                auth_burst: 5,
                api_per_minute: 100,
                api_burst: 10,
            },
            telemetry: TelemetryConfig {
                log_format: LogFormat::Pretty,
                log_filter: "info".into(),
            },
        }
    }

    #[test]
    fn sample_config_is_valid() {
        sample().validate().unwrap();
    }

    #[test]
    fn rejects_short_jwt_secret() {
        let mut c = sample();
        c.auth.jwt_secret = "too-short".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_part_size_below_s3_minimum() {
        let mut c = sample();
        c.uploads.part_size = MIB;
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_too_many_parts() {
        let mut c = sample();
        c.uploads.part_size = S3_MIN_PART_SIZE;
        c.uploads.max_file_size = S3_MIN_PART_SIZE * (S3_MAX_PARTS + 1);
        assert!(c.validate().is_err());
    }

    #[test]
    fn production_requires_kms_and_real_s3() {
        let mut c = sample();
        c.environment = Environment::Production;
        assert!(c.validate().is_err(), "missing KMS key must fail");
        c.storage.sse_kms_key_id = Some("arn:aws:kms:...".into());
        c.validate().unwrap();
        c.storage.endpoint_url = Some("http://localhost:9000".into());
        assert!(
            c.validate().is_err(),
            "custom endpoint must fail in production"
        );
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("0123456789abcdef"));
    }
}
