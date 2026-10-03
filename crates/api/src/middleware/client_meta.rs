//! Who is calling: client IP, user agent and request id, for audit logs and rate limiting.

use std::{convert::Infallible, net::SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::state::AppState;

pub const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_USER_AGENT_LEN: usize = 256;

#[derive(Debug, Clone, Default)]
pub struct ClientMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

impl FromRequestParts<AppState> for ClientMeta {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0);
        Ok(Self {
            ip: client_ip(&parts.headers, peer, state.config.http.trust_proxy_headers),
            user_agent: header_str(&parts.headers, "user-agent")
                .map(|ua| ua.chars().take(MAX_USER_AGENT_LEN).collect()),
            request_id: header_str(&parts.headers, REQUEST_ID_HEADER).map(str::to_owned),
        })
    }
}

/// Resolve the client IP.
///
/// `X-Forwarded-For` is attacker-controlled: anyone can send `X-Forwarded-For: 1.2.3.4`. It is
/// only meaningful when we sit behind a proxy we trust (the ALB), which *appends* the address it
/// saw. So we take the **right-most** entry, never the left-most, and only when configured to
/// trust proxy headers. Otherwise we use the TCP peer address.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trust_proxy_headers: bool,
) -> Option<String> {
    if trust_proxy_headers
        && let Some(xff) = header_str(headers, "x-forwarded-for")
        && let Some(last) = xff.rsplit(',').map(str::trim).find(|s| !s.is_empty())
        && last.parse::<std::net::IpAddr>().is_ok()
    {
        return Some(last.to_owned());
    }
    peer.map(|addr| addr.ip().to_string())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", xff.parse().unwrap());
        h
    }

    #[test]
    fn ignores_forwarded_for_when_not_behind_trusted_proxy() {
        let peer = Some("10.0.0.5:1234".parse().unwrap());
        assert_eq!(
            client_ip(&headers("6.6.6.6"), peer, false).as_deref(),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn uses_rightmost_forwarded_for_entry_behind_proxy() {
        let peer = Some("10.0.0.5:1234".parse().unwrap());
        // The client spoofed "6.6.6.6"; the ALB appended the real address.
        let h = headers("6.6.6.6, 203.0.113.7");
        assert_eq!(client_ip(&h, peer, true).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn falls_back_to_peer_on_garbage_header() {
        let peer = Some("10.0.0.5:1234".parse().unwrap());
        assert_eq!(
            client_ip(&headers("not-an-ip"), peer, true).as_deref(),
            Some("10.0.0.5")
        );
    }
}
