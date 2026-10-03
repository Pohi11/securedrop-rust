//! Request IDs: one id per request, in every log line and in the response.
//!
//! When a user reports "I got an internal error", the `x-request-id` from their response finds
//! the exact log lines (and audit rows) for that request. A load balancer or another service
//! may already have assigned one; we keep it if it looks sane, so one id follows the request
//! across systems.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use super::client_meta::REQUEST_ID_HEADER;

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

pub async fn assign(mut request: Request, next: Next) -> Response {
    let header = HeaderName::from_static(REQUEST_ID_HEADER);

    // Untrusted input ends up in logs: accept only short, boring ids (no newlines, no
    // control characters, no log-injection payloads); otherwise mint our own.
    let incoming = request
        .headers()
        .get(&header)
        .and_then(|v| v.to_str().ok())
        .filter(|id| is_valid(id))
        .map(str::to_owned);
    let id = incoming.unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(value) = HeaderValue::from_str(&id) {
        // Overwrite, so downstream code (ClientMeta, audit) sees the sanitised id.
        request.headers_mut().insert(header.clone(), value.clone());
        request.extensions_mut().insert(RequestId(id));
        let mut response = next.run(request).await;
        response.headers_mut().insert(header, value);
        response
    } else {
        next.run(request).await
    }
}

fn is_valid(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::is_valid;

    #[test]
    fn rejects_injection_attempts() {
        assert!(is_valid("3f1c2b6e-1d2a-4c55-9a3b-2b1f0c9d8e7a"));
        assert!(!is_valid(""));
        assert!(!is_valid("abc\ninjected log line"));
        assert!(!is_valid(&"a".repeat(65)));
        assert!(!is_valid("<script>"));
    }
}
