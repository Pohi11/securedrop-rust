//! Distributed rate limiting (GCRA) in Redis.
//!
//! **Why Redis?** The API runs as several ECS tasks behind a load balancer. An in-memory
//! limiter would give each task its own budget (N replicas = N× the limit) and would reset on
//! every deploy. A shared Redis gives one budget per client across the fleet.
//!
//! **Why GCRA (Generic Cell Rate Algorithm)?** It behaves like a token bucket (steady rate plus
//! a burst allowance) but stores a *single number* per client: the "theoretical arrival time"
//! (TAT) of the next request. No background refill, no per-request lists like sliding-window
//! logs, and the whole check-and-update runs atomically in one Lua script.

use std::{net::SocketAddr, sync::LazyLock, time::Duration};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::client_meta::client_ip;
use crate::{error::AppError, state::AppState};

/// Atomic GCRA step. Uses Redis' own clock (`TIME`) so API replicas with skewed clocks agree.
///
/// KEYS[1] = bucket key; ARGV[1] = emission interval (ms per request);
/// ARGV[2] = burst tolerance (ms) = emission interval × (burst − 1).
/// Returns {allowed (1/0), retry_after_ms}.
const GCRA_LUA: &str = r#"
local emission = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local tat = tonumber(redis.call('GET', KEYS[1])) or now
if tat < now then tat = now end
local ahead = tat - now
if ahead > tolerance then
  return {0, ahead - tolerance}
end
local new_tat = tat + emission
redis.call('SET', KEYS[1], new_tat, 'PX', new_tat - now)
return {1, 0}
"#;

static GCRA: LazyLock<redis::Script> = LazyLock::new(|| redis::Script::new(GCRA_LUA));

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub name: &'static str,
    pub per_minute: u32,
    pub burst: u32,
    /// What to do when Redis is unreachable.
    pub fail_open: bool,
}

pub enum Verdict {
    Allow,
    Deny { retry_after: Duration },
}

/// Run one GCRA step for `key` under `policy`.
pub async fn check(state: &AppState, policy: Policy, key: &str) -> redis::RedisResult<Verdict> {
    let emission_ms = 60_000 / u64::from(policy.per_minute.max(1));
    let tolerance_ms = emission_ms * u64::from(policy.burst.max(1) - 1);
    let full_key = format!("{}rl:{}:{key}", state.config.redis.key_prefix, policy.name);

    let mut conn = state.redis.clone();
    let (allowed, retry_ms): (i64, i64) = GCRA
        .key(full_key)
        .arg(emission_ms)
        .arg(tolerance_ms)
        .invoke_async(&mut conn)
        .await?;

    Ok(if allowed == 1 {
        Verdict::Allow
    } else {
        Verdict::Deny {
            retry_after: Duration::from_millis(u64::try_from(retry_ms).unwrap_or(0)),
        }
    })
}

/// Middleware for unauthenticated, abuse-prone routes (`/auth/*`, share-link redemption).
/// Keyed by client IP. Fails **closed**: if we can't count login attempts, we don't allow
/// unlimited password guessing.
pub async fn limit_by_ip(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let rl = &state.config.rate_limit;
    let policy = Policy {
        name: "auth",
        per_minute: rl.auth_per_minute,
        burst: rl.auth_burst,
        fail_open: false,
    };
    let key = format!("ip:{}", ip_of(&state, &request));
    enforce(&state, policy, &key, request, next).await
}

/// Middleware for the authenticated API. Keyed by user id when the request carries a valid
/// access token (so users behind one NAT don't share a budget), otherwise by IP. Fails
/// **open**: a Redis outage shouldn't take down uploads and downloads.
pub async fn limit_by_user(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let rl = &state.config.rate_limit;
    let policy = Policy {
        name: "api",
        per_minute: rl.api_per_minute,
        burst: rl.api_burst,
        fail_open: true,
    };
    // Signature check only (no Redis revocation lookup): this just picks the bucket. The
    // handler's AuthUser extractor still does full authentication.
    let user = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .and_then(|(_, token)| state.jwt.verify(token.trim()).ok());
    let key = match user {
        Some(claims) => format!("user:{}", claims.sub),
        None => format!("ip:{}", ip_of(&state, &request)),
    };
    enforce(&state, policy, &key, request, next).await
}

async fn enforce(
    state: &AppState,
    policy: Policy,
    key: &str,
    request: Request,
    next: Next,
) -> Response {
    if !state.config.rate_limit.enabled {
        return next.run(request).await;
    }
    match check(state, policy, key).await {
        Ok(Verdict::Allow) => next.run(request).await,
        Ok(Verdict::Deny { retry_after }) => {
            metrics::counter!("securedrop_rate_limited_total", "policy" => policy.name)
                .increment(1);
            tracing::info!(policy = policy.name, key, "rate limited");
            AppError::RateLimited { retry_after }.into_response()
        }
        Err(err) if policy.fail_open => {
            tracing::warn!(%err, policy = policy.name, "rate limiter unavailable; failing open");
            next.run(request).await
        }
        Err(err) => {
            tracing::error!(%err, policy = policy.name, "rate limiter unavailable; failing closed");
            AppError::Unavailable.into_response()
        }
    }
}

fn ip_of(state: &AppState, request: &Request) -> String {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    client_ip(
        request.headers(),
        peer,
        state.config.http.trust_proxy_headers,
    )
    .unwrap_or_else(|| "unknown".into())
}
