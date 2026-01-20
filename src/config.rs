use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use jsonschema::JSONSchema;
use schemars::{JsonSchema, schema_for};
use serde::Deserialize;
use serde_json::Value;

use crate::error::AppError;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ProviderSettings {
    pub issuer: String,
    pub token_ttl_seconds: u64,
    pub listen: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    #[schemars(default)]
    pub audience: Option<String>,
    #[serde(default)]
    #[schemars(default)]
    pub scopes: Vec<String>,
    #[serde(default = "empty_metadata")]
    #[schemars(default = "empty_metadata")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default = "default_enabled")]
    #[schemars(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    #[schemars(default)]
    pub token_ttl_seconds: Option<u64>,
}

const fn default_enabled() -> bool {
    true
}

fn empty_metadata() -> BTreeMap<String, Value> {
    BTreeMap::new()
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    pub audience: Option<String>,
    pub allowed_scopes: BTreeSet<String>,
    pub metadata: BTreeMap<String, Value>,
    pub token_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub provider: ProviderSettings,
    pub clients: HashMap<String, Client>,
    pub token_template: Value,
    pub config_root: PathBuf,
}

impl LoadedConfig {
    pub fn load_from_directory<P: AsRef<Path>>(path: P) -> Result<Self, AppError> {
        let root = path.as_ref();
        let provider: ProviderSettings = read_json(root.join("provider.json"))?;
        let raw_clients: Value = read_json_value(root.join("clients.json"))?;
        validate_json(&schema_for!(Vec<ClientConfig>), &raw_clients)?;
        let clients_vec: Vec<ClientConfig> = serde_json::from_value(raw_clients)?;
        let clients = build_clients(clients_vec);
        if clients.is_empty() {
            return Err(AppError::Config("no active clients configured".into()));
        }

        let token_template: Value = read_json(root.join("token_template.json"))?;
        if !token_template.is_object() {
            return Err(AppError::Config(
                "token template must be a JSON object".into(),
            ));
        }

        Ok(Self {
            provider,
            clients,
            token_template,
            config_root: root.to_path_buf(),
        })
    }

    pub fn key_path(&self) -> PathBuf {
        self.config_root.join("keys").join("signing-key.pem")
    }
}

fn build_clients(clients: Vec<ClientConfig>) -> HashMap<String, Client> {
    let mut map = HashMap::new();
    for client in clients.into_iter().filter(|c| c.enabled) {
        map.insert(
            client.client_id.clone(),
            Client {
                client_id: client.client_id,
                client_secret: client.client_secret,
                audience: client.audience,
                allowed_scopes: client.scopes.into_iter().collect(),
                metadata: client.metadata,
                token_ttl_seconds: client.token_ttl_seconds,
            },
        );
    }
    map
}

fn read_json<T: for<'de> Deserialize<'de>>(path: PathBuf) -> Result<T, AppError> {
    let data = fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(AppError::from)
}

fn read_json_value(path: PathBuf) -> Result<Value, AppError> {
    let data = fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(AppError::from)
}

fn validate_json(schema: &schemars::schema::RootSchema, value: &Value) -> Result<(), AppError> {
    let schema_value = serde_json::to_value(schema)
        .map_err(|err| AppError::Schema(format!("failed to serialize schema: {err}")))?;
    let compiled = JSONSchema::compile(&schema_value)
        .map_err(|err| AppError::Schema(format!("schema compilation failed: {err}")))?;
    if let Err(errors) = compiled.validate(value) {
        let joined = errors
            .map(|err| err.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(AppError::Schema(joined));
    }
    Ok(())
}
