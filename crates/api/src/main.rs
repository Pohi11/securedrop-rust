use securedrop_api::{config::Config, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    telemetry::init_tracing(&config.telemetry)?;
    securedrop_api::run(config).await
}
