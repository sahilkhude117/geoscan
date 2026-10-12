use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use geoscan_api::{AppState, Config, router};

#[derive(Parser)]
#[command(about = "Serve the local GeoScan HTTP API")]
struct Args {
    #[arg(long, env = "GEOSCAN_BIND", default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
    #[arg(long, env = "GEOSCAN_DB", default_value = "geoscan.db")]
    db: PathBuf,
    #[arg(long, env = "GEOSCAN_NUCLEI", default_value = "nuclei")]
    nuclei: PathBuf,
    /// Exact application URLs the web app may scan; comma-separated or repeated.
    #[arg(
        long,
        env = "GEOSCAN_ALLOWED_TARGETS",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:8080/geoserver"
    )]
    allow_target: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !args.bind.ip().is_loopback() {
        return Err("This local API must bind to a loopback address".into());
    }
    // Bind first: a second instance on this port must not recover live jobs.
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    let state = AppState::new(Config {
        database: args.db,
        engine: args.nuclei,
        allowed_targets: args.allow_target,
    })
    .await?;
    println!("GeoScan API listening at http://{}", listener.local_addr()?);
    axum::serve(listener, router(state.clone()))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    state.shutdown().await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Could not listen for termination");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
