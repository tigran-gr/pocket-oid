mod config;
mod error;
mod key;
mod metadata;
mod token;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use config::{AppConfig, Client};
use error::AppError;
use key::{JsonWebKeySet, KeyStore};
use metadata::{DiscoveryDocument, discovery_document};
use subtle::ConstantTimeEq;
use token::{TokenRequest, TokenResponse, TokenService, parse_scope};
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    clients: Arc<HashMap<String, Client>>,
    key_store: KeyStore,
    discovery_document: DiscoveryDocument,
    token_service: TokenService,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let config = AppConfig::load_from_dir("config").context("failed to load configuration")?;
    let key_store =
        KeyStore::from_configs(&config.signing_keys).context("failed to load signing keys")?;
    let token_service = TokenService::new(
        config.issuer.clone(),
        config.token_ttl,
        config.token_template.clone(),
        key_store.clone(),
    );

    let state = Arc::new(AppState {
        clients: Arc::new(config.clients),
        discovery_document: discovery_document(&config.issuer),
        key_store,
        token_service,
    });

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(handle_discovery))
        .route("/jwks.json", get(handle_jwks))
        .route("/oauth/token", post(handle_token))
        .route("/healthz", get(handle_health))
        .route("/readyz", get(handle_ready))
        .with_state(state);

    let addr = resolve_listen_address();
    info!("listening", %addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;

    Ok(())
}

fn resolve_listen_address() -> SocketAddr {
    let host = std::env::var("POCKET_OID_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("POCKET_OID_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080u16);
    let ip: IpAddr = host.parse().unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));
    SocketAddr::from((ip, port))
}

async fn handle_discovery(State(state): State<SharedState>) -> Json<DiscoveryDocument> {
    Json(state.discovery_document.clone())
}

async fn handle_jwks(State(state): State<SharedState>) -> Json<JsonWebKeySet> {
    Json(state.key_store.jwks())
}

async fn handle_token(
    State(state): State<SharedState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    if request.grant_type != "client_credentials" {
        return Err(AppError::unsupported_grant_type());
    }

    let client = state
        .clients
        .get(&request.client_id)
        .ok_or_else(|| AppError::invalid_client())?;

    if subtle_secret_compare(&client.client_secret, &request.client_secret) == false {
        return Err(AppError::invalid_client());
    }

    let scopes = parse_scope(request.scope);
    let token = state
        .token_service
        .issue_token(client, &scopes)
        .map_err(|err| {
            error!(?err, "token issuance failed");
            AppError::from(err)
        })?;

    Ok(Json(token))
}

async fn handle_health() -> &'static str {
    "ok"
}

async fn handle_ready(State(state): State<SharedState>) -> Result<&'static str, AppError> {
    if state.clients.is_empty() {
        return Err(AppError::server_error("no active clients configured"));
    }
    Ok("ready")
}

fn subtle_secret_compare(expected: &str, provided: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();
    bool::from(expected_bytes.ct_eq(provided_bytes))
}
