use std::time::Duration;

use axum::{Json, extract::State, http::StatusCode};
use securedrop_common::HealthResponse;
use serde_json::{Value, json};

use crate::state::AppState;

/// Liveness: "is the process up and serving HTTP?" Deliberately checks no dependencies,
/// so a database blip does not make the orchestrator kill healthy containers.
pub async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Readiness: "should the load balancer send traffic here?" Checks every dependency a
/// request needs, concurrently and with a timeout each, so one hung dependency can't make
/// the probe itself hang. Returns 503 with per-dependency detail if any check fails.
pub async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let db = async {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&state.db)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let redis = async {
        let mut conn = state.redis.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let storage = async {
        state
            .storage
            .health_check()
            .await
            .map_err(|e| format!("{e:#}"))
    };

    let (db, redis, storage) =
        tokio::join!(with_timeout(db), with_timeout(redis), with_timeout(storage));

    let mut ready = true;
    let mut checks = serde_json::Map::new();
    for (name, result) in [("database", db), ("redis", redis), ("storage", storage)] {
        match result {
            Ok(()) => {
                checks.insert(name.into(), json!("ok"));
            }
            Err(err) => {
                ready = false;
                // Details go to logs; the probe response only says which dependency failed.
                tracing::warn!(dependency = name, error = %err, "readiness check failed");
                checks.insert(name.into(), json!("unavailable"));
            }
        }
    }
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({ "status": if ready { "ready" } else { "not_ready" }, "checks": checks })),
    )
}

async fn with_timeout(fut: impl Future<Output = Result<(), String>>) -> Result<(), String> {
    tokio::time::timeout(CHECK_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| Err("timed out".into()))
}
