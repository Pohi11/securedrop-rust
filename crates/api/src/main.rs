use std::time::Duration;

use securedrop_api::{config::Config, telemetry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `securedrop-api healthcheck`: used by the container HEALTHCHECK. The runtime image is
    // distroless (no shell, no curl), so the binary probes its own liveness endpoint.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck().await;
    }

    let config = Config::from_env()?;
    telemetry::init_tracing(&config.telemetry)?;
    securedrop_api::run(config).await
}

async fn healthcheck() -> anyhow::Result<()> {
    let port = std::env::var("BIND_ADDR")
        .ok()
        .and_then(|a| a.rsplit(':').next().map(str::to_owned))
        .unwrap_or_else(|| "8080".into());
    let probe = async {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
        stream
            .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await?;
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await?;
        anyhow::Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    };
    let status_line = tokio::time::timeout(Duration::from_secs(2), probe).await??;
    if status_line.starts_with("HTTP/1.0 200") || status_line.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        anyhow::bail!(
            "unhealthy: {}",
            status_line.lines().next().unwrap_or_default()
        )
    }
}
