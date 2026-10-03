//! HTTP-level hardening layers.

use std::time::Duration;

use axum::{
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use tower::layer::util::Stack;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{AllowOrigin, CorsLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

use crate::error::AppError;

pub fn catch_panic() -> CatchPanicLayer<fn(Box<dyn std::any::Any + Send>) -> Response> {
    fn handle(_panic: Box<dyn std::any::Any + Send>) -> Response {
        tracing::error!("handler panicked");
        AppError::Internal(anyhow::anyhow!("handler panicked")).into_response()
    }
    CatchPanicLayer::custom(handle as fn(_) -> _)
}

pub fn sensitive_headers() -> SetSensitiveRequestHeadersLayer {
    SetSensitiveRequestHeadersLayer::new([header::AUTHORIZATION, header::COOKIE])
}

pub fn timeout(duration: Duration) -> TimeoutLayer {
    // 503 rather than 408: the *server* ran out of time, not the client.
    TimeoutLayer::with_status_code(StatusCode::SERVICE_UNAVAILABLE, duration)
}

/// CORS for browser clients. Exact-match origin allowlist; never `*` with credentials.
/// We authenticate with bearer tokens (not cookies), so no `allow_credentials`. That also
/// means a malicious site can't make a logged-in user's browser call the API with ambient
/// credentials (classic CSRF).
pub fn cors(allowed_origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(600))
}

/// Defensive response headers on every response.
pub struct SecurityHeaders;

type H = SetResponseHeaderLayer<HeaderValue>;

impl SecurityHeaders {
    #[allow(clippy::type_complexity)]
    pub fn layer() -> Stack<H, Stack<H, Stack<H, Stack<H, Stack<H, H>>>>> {
        let set = |name: HeaderName, value: &'static str| {
            SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
        };
        Stack::new(
            // Responses contain tokens and presigned URLs: never cache them anywhere.
            set(header::CACHE_CONTROL, "no-store"),
            Stack::new(
                // Don't let browsers guess a content type (MIME-sniffing XSS).
                set(header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                Stack::new(
                    // This is a JSON API: it should never be framed or load anything.
                    set(
                        header::CONTENT_SECURITY_POLICY,
                        "default-src 'none'; frame-ancestors 'none'",
                    ),
                    Stack::new(
                        set(header::X_FRAME_OPTIONS, "DENY"),
                        Stack::new(
                            set(header::REFERRER_POLICY, "no-referrer"),
                            // Only honoured over HTTPS (the ALB terminates TLS in production).
                            set(
                                header::STRICT_TRANSPORT_SECURITY,
                                "max-age=63072000; includeSubDomains",
                            ),
                        ),
                    ),
                ),
            ),
        )
    }
}
