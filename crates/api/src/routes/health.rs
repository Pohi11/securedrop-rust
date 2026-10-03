use axum::Json;
use securedrop_common::HealthResponse;

/// Liveness: "is the process up and serving HTTP?" Deliberately checks no dependencies,
/// so a database blip does not make the orchestrator kill healthy containers.
pub async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}
