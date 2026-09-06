use std::{
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
};

use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use pocket_oid::app::AppState;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(
    name = "pocket-oid",
    version,
    about = "A minimal OpenID Connect provider",
    after_help = "Configuration:\n  Set POCKET_OID_CONFIG_DIR to the directory containing provider.json,\n  clients.json, users.json, and token_template.json. Defaults to ./config.\n  The default signing key is keys/signing-key.pem unless signing_key_paths\n  selects another file. Client signing_algorithm overrides require keys\n  for any additional algorithms in provider.json's signing_key_paths."
)]
struct Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Cli::parse();
    let config_dir = std::env::var("POCKET_OID_CONFIG_DIR").unwrap_or_else(|_| "config".into());
    let configured_log_dir = configured_log_dir(Path::new(&config_dir));
    let logging_to_file = configured_log_dir.is_some();
    init_tracing(Path::new(&config_dir), configured_log_dir.as_deref())?;

    if let Err(error) = run(Path::new(&config_dir)).await {
        if logging_to_file {
            tracing::error!(error = %format!("{error:#}"), "pocket-oid stopped");
            process::exit(1);
        }
        return Err(error);
    }
    Ok(())
}

async fn run(config_dir: &Path) -> anyhow::Result<()> {
    let state = AppState::initialize(config_dir).with_context(|| {
        format!(
            "failed to initialize provider using config at {}",
            config_dir.display()
        )
    })?;
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

fn configured_log_dir(config_dir: &Path) -> Option<PathBuf> {
    let path = config_dir.join("provider.json");
    let data = fs::read_to_string(path).ok()?;
    let provider: serde_json::Value = serde_json::from_str(&data).ok()?;
    provider.get("log_dir")?.as_str().map(PathBuf::from)
}

fn init_tracing(config_dir: &Path, configured_log_dir: Option<&Path>) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if let Some(configured_log_dir) = configured_log_dir {
        let log_dir = resolve_log_dir(config_dir, configured_log_dir);
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;
        let log_path = log_file_path(&log_dir);
        let log_file = File::create(&log_path)
            .with_context(|| format!("failed to create log file {}", log_path.display()))?;
        fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(log_file)
            .try_init()
            .map_err(|error| anyhow::anyhow!("failed to initialize file logging: {error}"))?;
    } else {
        fmt().with_env_filter(filter).with_target(false).init();
    }
    Ok(())
}

fn resolve_log_dir(config_dir: &Path, configured_log_dir: &Path) -> PathBuf {
    if configured_log_dir.is_absolute() {
        configured_log_dir.to_path_buf()
    } else {
        config_dir.join(configured_log_dir)
    }
}

fn log_file_path(log_dir: &Path) -> PathBuf {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    log_dir.join(format!("pocket-oid-{timestamp}-{}.log", process::id()))
}
