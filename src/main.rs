use std::{
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
};

use anyhow::Context;
use chrono::Utc;
use clap::{Parser, Subcommand};
use pocket_oid::{admins::AdminStore, app::AppState};
use tracing_subscriber::{EnvFilter, fmt};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "pocket-oid",
    version,
    about = "A minimal OpenID Connect provider",
    after_help = "Configuration:\n  Set POCKET_OID_CONFIG_DIR to the directory containing provider.json,\n  clients.json, users.json, and token_template.json. Defaults to ./config.\n  Administrator commands additionally use admins.json.\n  The default signing key is keys/signing-key.pem unless signing_key_paths\n  selects another file. Client signing_algorithm overrides require keys\n  for any additional algorithms in provider.json's signing_key_paths."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage local administrator accounts.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Create an administrator account.
    Create {
        /// Username for the new administrator.
        username: String,
    },
    /// List administrator accounts.
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_dir = std::env::var("POCKET_OID_CONFIG_DIR").unwrap_or_else(|_| "config".into());
    if let Some(command) = cli.command {
        return run_command(command, Path::new(&config_dir));
    }

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

fn run_command(command: Command, config_dir: &Path) -> anyhow::Result<()> {
    match command {
        Command::Admin { command } => run_admin_command(command, config_dir),
    }
}

fn run_admin_command(command: AdminCommand, config_dir: &Path) -> anyhow::Result<()> {
    let store = AdminStore::load_from_directory(config_dir)?;
    match command {
        AdminCommand::Create { username } => {
            let password = Zeroizing::new(
                rpassword::prompt_password("Password: ")
                    .context("failed to read administrator password")?,
            );
            let confirmation = Zeroizing::new(
                rpassword::prompt_password("Confirm password: ")
                    .context("failed to read administrator password confirmation")?,
            );
            if password.as_str() != confirmation.as_str() {
                anyhow::bail!("passwords do not match");
            }
            let admin = store.create(&username, password.as_str())?;
            println!("Created administrator '{}'.", admin.username);
        }
        AdminCommand::List => print_admins(&store.list()?),
    }
    Ok(())
}

fn print_admins(admins: &[pocket_oid::admins::AdminRecord]) {
    if admins.is_empty() {
        println!("No administrator accounts found.");
        return;
    }
    let username_width = admins
        .iter()
        .map(|admin| admin.username.chars().count())
        .chain(std::iter::once("USERNAME".len()))
        .max()
        .unwrap_or("USERNAME".len());
    println!(
        "{:<username_width$}  {:<8}  CREATED_AT",
        "USERNAME", "STATUS"
    );
    for admin in admins {
        let status = if admin.enabled { "enabled" } else { "disabled" };
        println!(
            "{:<username_width$}  {status:<8}  {}",
            admin.username, admin.created_at
        );
    }
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

#[cfg(test)]
mod tests {
    use super::{AdminCommand, Cli, Command};
    use clap::Parser;

    #[test]
    fn parses_admin_create_command() {
        let cli = Cli::try_parse_from(["pocket-oid", "admin", "create", "alice"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::Create { username }
            }) if username == "alice"
        ));
    }

    #[test]
    fn parses_admin_list_command() {
        let cli = Cli::try_parse_from(["pocket-oid", "admin", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Admin {
                command: AdminCommand::List
            })
        ));
    }

    #[test]
    fn no_subcommand_still_selects_server_mode() {
        let cli = Cli::try_parse_from(["pocket-oid"]).unwrap();
        assert!(cli.command.is_none());
    }
}
