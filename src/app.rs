use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Deref,
    path::Path,
    sync::Arc,
};

use axum::{
    Router,
    routing::{get, post},
};
use serde::Serialize;
use tower_http::trace::TraceLayer;

use crate::{
    auth::AuthStore,
    config::{Client, LoadedConfig, ProviderSettings, SigningAlgorithm, TrustedProviderConfig},
    crypto::{JwkSet, KeyMaterial, load_signing_key},
    error::AppError,
    handlers,
    token::TokenTemplate,
    upstream::UpstreamClient,
};

#[derive(Clone)]
pub struct AppState(Arc<ApplicationState>);

pub struct ApplicationState {
    pub provider: ProviderSettings,
    pub clients: HashMap<String, Client>,
    pub users: HashMap<String, crate::config::User>,
    pub trusted_providers: HashMap<String, TrustedProviderConfig>,
    pub upstream_client: UpstreamClient,
    pub token_template: TokenTemplate,
    pub signing_keys: BTreeMap<SigningAlgorithm, KeyMaterial>,
    pub jwk_set: JwkSet,
    pub discovery: DiscoveryDocument,
    pub auth_store: AuthStore,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
}

impl AppState {
    pub fn initialize(config_dir: &Path) -> Result<Self, AppError> {
        let config = LoadedConfig::load_from_directory(config_dir)
            .map_err(|err| AppError::Config(format!("failed to load configuration: {err}")))?;
        let signing_keys = load_signing_keys(&config)?;
        let jwk_set = JwkSet {
            keys: signing_keys.values().map(|key| key.jwk.clone()).collect(),
        };
        let upstream_client = UpstreamClient::new()?;
        let scopes_supported = collect_scopes(&config.clients);
        let discovery = DiscoveryDocument::new(&config.provider, &scopes_supported, &signing_keys);
        Ok(Self(Arc::new(ApplicationState {
            provider: config.provider,
            clients: config.clients,
            users: config.users,
            trusted_providers: config.trusted_providers,
            upstream_client,
            token_template: TokenTemplate::new(config.token_template),
            signing_keys,
            jwk_set,
            discovery,
            auth_store: AuthStore::default(),
        })))
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(handlers::openid_configuration),
            )
            .route("/jwks.json", get(handlers::jwks))
            .route("/oauth/token", post(handlers::token_endpoint))
            .route("/authorize", get(handlers::authorize))
            .route("/login", post(handlers::login))
            .route("/consent", post(handlers::consent))
            .route(
                "/reauth/callback/:provider_id",
                get(handlers::reauth_callback),
            )
            .route(
                "/reauth/consent/:transaction_id",
                get(handlers::reauth_consent_page),
            )
            .route("/reauth/consent", post(handlers::reauth_consent))
            .route("/healthz", get(handlers::healthz))
            .route("/readyz", get(handlers::readyz))
            .with_state(self.clone())
            .layer(TraceLayer::new_for_http())
    }
}

impl Deref for AppState {
    type Target = ApplicationState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DiscoveryDocument {
    fn new(
        provider: &ProviderSettings,
        scopes_supported: &[String],
        signing_keys: &BTreeMap<SigningAlgorithm, KeyMaterial>,
    ) -> Self {
        let issuer = provider.issuer.trim_end_matches('/').to_string();
        let authorization_endpoint = format!("{issuer}/authorize");
        let token_endpoint = format!("{issuer}/oauth/token");
        let jwks_uri = format!("{issuer}/jwks.json");
        Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            grant_types_supported: vec![
                "client_credentials".to_string(),
                "authorization_code".to_string(),
            ],
            response_types_supported: vec!["code".to_string(), "token".to_string()],
            subject_types_supported: vec!["public".to_string()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string()],
            id_token_signing_alg_values_supported: signing_keys
                .keys()
                .map(|algorithm| algorithm.as_str().to_string())
                .collect(),
            scopes_supported: scopes_supported.to_vec(),
        }
    }
}

fn load_signing_keys(
    config: &LoadedConfig,
) -> Result<BTreeMap<SigningAlgorithm, KeyMaterial>, AppError> {
    let algorithms: BTreeSet<_> = std::iter::once(config.provider.signing_algorithm)
        .chain(
            config
                .clients
                .values()
                .filter_map(|client| client.signing_algorithm),
        )
        .collect();
    let mut keys = BTreeMap::new();
    let mut key_ids = BTreeSet::new();
    for algorithm in algorithms {
        let path = config.key_path_for(algorithm)?;
        let key = load_signing_key(&path, algorithm).map_err(|error| {
            AppError::Config(format!(
                "failed to load {} signing key from '{}': {error}",
                algorithm.as_str(),
                path.display()
            ))
        })?;
        // Keep each public key bound to one algorithm, with an unambiguous kid.
        if !key_ids.insert(key.kid.clone()) {
            return Err(AppError::Config(format!(
                "{} reuses a signing key already configured for another algorithm; use distinct keys",
                algorithm.as_str()
            )));
        }
        keys.insert(algorithm, key);
    }
    Ok(keys)
}

fn collect_scopes(clients: &HashMap<String, Client>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for client in clients.values() {
        for scope in &client.allowed_scopes {
            set.insert(scope.clone());
        }
    }
    set.into_iter().collect()
}
