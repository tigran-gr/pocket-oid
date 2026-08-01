use std::{net::SocketAddr, path::Path};

use anyhow::Context;
use clap::Parser;
use pocket_oid::app::AppState;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(
    name = "pocket-oid",
    version,
    about = "A minimal OpenID Connect provider",
    after_help = "Configuration:\n  Set POCKET_OID_CONFIG_DIR to the directory containing provider.json,\n  clients.json, users.json, token_template.json, and keys/signing-key.pem.\n  Defaults to ./config."
)]
struct Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Cli::parse();
    init_tracing();
    let config_dir = std::env::var("POCKET_OID_CONFIG_DIR").unwrap_or_else(|_| "config".into());
    let state = AppState::initialize(Path::new(&config_dir))
        .with_context(|| format!("failed to initialize provider using config at {config_dir}"))?;
    let router: axum::Router = state.router();
    let addr: SocketAddr = state
        .provider
        .listen
        .parse()
        .context("invalid listen address in provider configuration")?;

    tracing::info!(%addr, issuer = %state.provider.issuer, "starting pocket-oid");

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
