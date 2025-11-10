use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize, Clone)]
pub struct SigningKeyConfig {
    pub id: String,
    #[serde(rename = "private_key_path")]
    pub private_key_path: PathBuf,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "RS256".to_string()
}

#[derive(Debug, Deserialize)]
struct RawSettings {
    pub issuer: String,
    #[serde(default = "default_ttl")]
    pub token_ttl_seconds: u64,
    pub signing_keys: Vec<SigningKeyConfig>,
}

fn default_ttl() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
struct RawClient {
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub default_scope: Option<String>,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_metadata() -> Value {
    Value::Object(Default::default())
}

fn default_active() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub default_scope: Option<String>,
    pub metadata: Value,
    pub active: bool,
}

impl From<RawClient> for Client {
    fn from(value: RawClient) -> Self {
        Self {
            client_id: value.client_id,
            client_secret: value.client_secret,
            audience: value.audience,
            scopes: value.scopes,
            default_scope: value.default_scope,
            metadata: value.metadata,
            active: value.active,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub issuer: String,
    pub token_ttl: Duration,
    pub clients: HashMap<String, Client>,
    pub token_template: Value,
    pub signing_keys: Vec<SigningKeyConfig>,
}

impl AppConfig {
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let dir = dir.as_ref();

        let settings_path = dir.join("settings.json");
        let settings: RawSettings = read_json(&settings_path)
            .with_context(|| format!("failed to load settings from {}", settings_path.display()))?;

        if settings.signing_keys.is_empty() {
            anyhow::bail!("at least one signing key must be configured");
        }

        let RawSettings {
            issuer,
            token_ttl_seconds,
            signing_keys: raw_signing_keys,
        } = settings;

        let mut signing_keys = Vec::new();
        for mut key in raw_signing_keys {
            if key.private_key_path.is_relative() {
                key.private_key_path = dir.join(&key.private_key_path);
            }
            signing_keys.push(key);
        }

        let clients_path = dir.join("clients.json");
        let client_entries: Vec<RawClient> = read_json(&clients_path)
            .with_context(|| format!("failed to load clients from {}", clients_path.display()))?;

        let mut clients = HashMap::new();
        for raw in client_entries {
            if raw.client_id.trim().is_empty() {
                anyhow::bail!("client_id cannot be empty");
            }
            if clients.contains_key(&raw.client_id) {
                anyhow::bail!("duplicate client_id detected: {}", raw.client_id);
            }
            let client: Client = raw.into();
            if client.active {
                clients.insert(client.client_id.clone(), client);
            }
        }

        let template_path = dir.join("token_template.json");
        let token_template: Value = read_json(&template_path).with_context(|| {
            format!(
                "failed to load token template from {}",
                template_path.display()
            )
        })?;

        Ok(Self {
            issuer,
            token_ttl: Duration::from_secs(token_ttl_seconds),
            clients,
            token_template,
            signing_keys,
        })
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse JSON from {}", path.display()))?;
    Ok(parsed)
}
