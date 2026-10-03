//! Logging/tracing setup.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{LogFormat, TelemetryConfig};

/// Install the global tracing subscriber. Call once, at startup.
pub fn init_tracing(config: &TelemetryConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.log_filter)?;
    let registry = tracing_subscriber::registry().with(filter);

    match config.log_format {
        // JSON lines are what CloudWatch Logs Insights queries best.
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true),
            )
            .try_init()?,
        LogFormat::Pretty => registry.with(fmt::layer().compact()).try_init()?,
    }
    Ok(())
}
