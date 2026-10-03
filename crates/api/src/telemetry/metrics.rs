//! Prometheus metrics.
//!
//! Code anywhere in the crate records metrics through the `metrics` facade macros
//! (`metrics::counter!`, `histogram!`). This module installs the Prometheus recorder that
//! backs those macros and serves the text exposition format on a **separate, internal
//! listener**: `/metrics` is never routed through the public load balancer (it reveals
//! traffic patterns and internal route names).

use std::{sync::OnceLock, time::Instant};

use axum::{
    Router,
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
    routing::get,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Latency buckets (seconds) for an API whose handlers do a few DB/Redis round trips.
const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Install the global recorder once per process (safe to call repeatedly and concurrently,
/// e.g. from parallel tests).
///
/// `get_or_init` matters here: with a plain "check, then set" two threads can both see the
/// cell empty, both build a recorder, and the loser then finds neither its own recorder
/// installed nor the winner's handle stored yet. `get_or_init` runs the closure exactly once
/// and makes every other caller wait for its result.
pub fn init() -> anyhow::Result<PrometheusHandle> {
    static HANDLE: OnceLock<Result<PrometheusHandle, String>> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            let recorder = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Full("http_request_duration_seconds".into()),
                    LATENCY_BUCKETS,
                )
                .map_err(|e| e.to_string())?
                .build_recorder();
            let handle = recorder.handle();
            metrics::set_global_recorder(recorder).map_err(|e| e.to_string())?;
            Ok(handle)
        })
        .clone()
        .map_err(|e| anyhow::anyhow!("failed to install metrics recorder: {e}"))
}

/// Router for the internal metrics listener.
pub fn router(handle: PrometheusHandle) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let handle = handle.clone();
            async move {
                handle.run_upkeep();
                handle.render()
            }
        }),
    )
}

/// Middleware recording request count and latency (RED metrics: Rate, Errors, Duration).
///
/// Labels use the *matched route template* (`/api/v1/files/{id}`), never the raw path:
/// raw paths contain ids, and one time series per file id would explode metric cardinality
/// (and the bill).
pub async fn track_http(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |p| p.as_str().to_string());

    let response = next.run(request).await;

    let status = response.status().as_u16().to_string();
    metrics::counter!("http_requests_total", "method" => method.clone(), "route" => route.clone(), "status" => status)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "route" => route)
        .record(start.elapsed().as_secs_f64());
    response
}
