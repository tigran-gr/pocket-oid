mod app;
mod config;
mod crypto;
mod error;
mod handlers;
mod token;

use std::{net::SocketAddr, path::Path};

use anyhow::Context;
use app::AppState;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config_dir = std::env::var("POCKET_OID_CONFIG_DIR").unwrap_or_else(|_| "config".into());
    let state = AppState::initialize(Path::new(&config_dir))
        .with_context(|| format!("failed to initialize provider using config at {config_dir}"))?;
    let router = state.router();
    let addr: SocketAddr = state
        .provider
        .listen
        .parse()
        .context("invalid listen address in provider configuration")?;

    tracing::info!("starting pocket-oid", %addr, issuer = %state.provider.issuer);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind listen socket")?;
    axum::serve(listener, router)
        .await
        .context("server error")?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}
