use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use jsonschema::JSONSchema;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::{error::AppError, users::UserStore};

pub use crate::users::{User, UserConfig, UsersConfig};

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ProviderSettings {
    pub name: String,
    pub issuer: String,
    pub token_ttl_seconds: u64,
    pub listen: String,
    #[serde(default)]
    #[schemars(default)]
    pub log_dir: Option<PathBuf>,
    #[serde(default)]
    #[schemars(default)]
    pub signing_algorithm: SigningAlgorithm,
    #[serde(default)]
    #[schemars(default)]
    pub signing_key_paths: BTreeMap<SigningAlgorithm, PathBuf>,
    #[serde(default)]
    #[schemars(default)]
    pub login_background_color: Option<String>,
}

#[derive(
    Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum SigningAlgorithm {
    #[default]
    RS256,
    ES256,
    PS256,
}

impl SigningAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::ES256 => "ES256",
            Self::PS256 => "PS256",
        }
    }

    pub const fn jwt_algorithm(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::PS256 => jsonwebtoken::Algorithm::PS256,
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    #[schemars(default)]
    pub signing_algorithm: Option<SigningAlgorithm>,
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
    #[serde(default)]
    #[schemars(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_response_types")]
    #[schemars(default = "default_response_types")]
    pub response_types: Vec<String>,
    #[serde(default = "default_pkce_required")]
    #[schemars(default = "default_pkce_required")]
    pub require_pkce: bool,
    #[serde(default)]
    #[schemars(default)]
    pub consent_mode: ConsentMode,
    #[serde(default)]
    #[schemars(default)]
    pub auth_mode: ClientAuthMode,
    #[serde(default)]
    #[schemars(default)]
    pub re_auth: Option<ReAuthClientConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    #[default]
    Local,
    ReAuth,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReAuthClientConfig {
    pub provider_id: String,
    #[serde(default)]
    #[schemars(default)]
    pub upstream_scopes: Vec<String>,
    #[serde(default)]
    #[schemars(default)]
    pub consent: ReAuthConsent,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReAuthConsent {
    #[default]
    Local,
    Skip,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct TrustedProviderConfig {
    pub provider_id: String,
    #[serde(rename = "type", default)]
    #[schemars(default)]
    pub provider_type: TrustedProviderType,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default)]
    #[schemars(default)]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    #[serde(default = "default_upstream_pkce_required")]
    #[schemars(default = "default_upstream_pkce_required")]
    pub require_pkce: bool,
    #[serde(default = "default_allowed_signing_algorithms")]
    #[schemars(default = "default_allowed_signing_algorithms")]
    pub allowed_signing_algorithms: Vec<SigningAlgorithm>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedProviderType {
    #[default]
    Oidc,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    #[default]
    ClientSecretPost,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    #[default]
    Always,
    Skip,
}

const fn default_enabled() -> bool {
    true
}

fn empty_metadata() -> BTreeMap<String, Value> {
    BTreeMap::new()
}

fn default_response_types() -> Vec<String> {
    vec!["token".to_string(), "code".to_string()]
}

const fn default_pkce_required() -> bool {
    false
}

const fn default_upstream_pkce_required() -> bool {
    true
}

fn default_allowed_signing_algorithms() -> Vec<SigningAlgorithm> {
    vec![SigningAlgorithm::RS256]
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    pub signing_algorithm: Option<SigningAlgorithm>,
    pub audience: Option<String>,
    pub allowed_scopes: BTreeSet<String>,
    pub metadata: BTreeMap<String, Value>,
    pub token_ttl_seconds: Option<u64>,
    pub redirect_uris: BTreeSet<String>,
    pub response_types: BTreeSet<String>,
    pub require_pkce: bool,
    pub consent_mode: ConsentMode,
    pub auth_mode: ClientAuthMode,
    pub re_auth: Option<ReAuthClientConfig>,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub provider: ProviderSettings,
    pub clients: HashMap<String, Client>,
    pub users: UserStore,
    pub trusted_providers: HashMap<String, TrustedProviderConfig>,
    pub token_template: Value,
    pub config_root: PathBuf,
}

impl LoadedConfig {
    pub fn load_from_directory<P: AsRef<Path>>(path: P) -> Result<Self, AppError> {
        let root = path.as_ref();
        let provider: ProviderSettings = read_json(root.join("provider.json"))?;
        validate_provider_settings(&provider)?;
        let raw_clients: Value = read_json_value(root.join("clients.json"))?;
        validate_json(&schema_for!(Vec<ClientConfig>), &raw_clients)?;
        let clients_vec: Vec<ClientConfig> = serde_json::from_value(raw_clients)?;
        let clients = build_clients(clients_vec)?;
        if clients.is_empty() {
            return Err(AppError::Config("no active clients configured".into()));
        }
        let raw_trusted_providers = read_json_value_optional(root.join("trusted_providers.json"))?
            .unwrap_or_else(|| Value::Array(Vec::new()));
        validate_json(
            &schema_for!(Vec<TrustedProviderConfig>),
            &raw_trusted_providers,
        )?;
        let trusted_providers_vec: Vec<TrustedProviderConfig> =
            serde_json::from_value(raw_trusted_providers)?;
        let trusted_providers = build_trusted_providers(trusted_providers_vec)?;
        validate_reauth_clients(&clients, &trusted_providers)?;
        let users_config: UsersConfig = read_json(root.join("users.json"))?;
        let users = UserStore::load(users_config, root)?;

        let token_template: Value = read_json(root.join("token_template.json"))?;
        if !token_template.is_object() {
            return Err(AppError::Config(
                "token template must be a JSON object".into(),
            ));
        }

        Ok(Self {
            provider,
            clients,
            users,
            trusted_providers,
            token_template,
            config_root: root.to_path_buf(),
        })
    }

    pub fn key_path(&self) -> PathBuf {
        self.config_root.join("keys").join("signing-key.pem")
    }

    pub fn key_path_for(&self, algorithm: SigningAlgorithm) -> Result<PathBuf, AppError> {
        if let Some(path) = self.provider.signing_key_paths.get(&algorithm) {
            return Ok(self.config_root.join(path));
        }
        if algorithm == self.provider.signing_algorithm {
            return Ok(self.key_path());
        }
        Err(AppError::Config(format!(
            "signing_key_paths must configure a key for client signing algorithm {}",
            algorithm.as_str()
        )))
    }
}

fn build_clients(clients: Vec<ClientConfig>) -> Result<HashMap<String, Client>, AppError> {
    let mut map = HashMap::new();
    for client in clients.into_iter().filter(|c| c.enabled) {
        if map.contains_key(&client.client_id) {
            return Err(AppError::Config(format!(
                "duplicate active client_id '{}'",
                client.client_id
            )));
        }
        map.insert(
            client.client_id.clone(),
            Client {
                client_id: client.client_id,
                client_secret: client.client_secret,
                signing_algorithm: client.signing_algorithm,
                audience: client.audience,
                allowed_scopes: client.scopes.into_iter().collect(),
                metadata: client.metadata,
                token_ttl_seconds: client.token_ttl_seconds,
                redirect_uris: client.redirect_uris.into_iter().collect(),
                response_types: client.response_types.into_iter().collect(),
                require_pkce: client.require_pkce,
                consent_mode: client.consent_mode,
                auth_mode: client.auth_mode,
                re_auth: client.re_auth,
            },
        );
    }
    Ok(map)
}

fn validate_provider_settings(provider: &ProviderSettings) -> Result<(), AppError> {
    if provider
        .log_dir
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        return Err(AppError::Config("log_dir must not be empty".into()));
    }

    for (algorithm, path) in &provider.signing_key_paths {
        if path.as_os_str().is_empty() {
            return Err(AppError::Config(format!(
                "signing_key_paths.{} must not be empty",
                algorithm.as_str()
            )));
        }
    }
    let Some(color) = provider.login_background_color.as_deref() else {
        return Ok(());
    };

    let valid_length = matches!(color.len(), 4 | 5 | 7 | 9);
    let valid_hex = color
        .strip_prefix('#')
        .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !valid_length || !valid_hex {
        return Err(AppError::Config(
            "login_background_color must be a #RGB, #RGBA, #RRGGBB, or #RRGGBBAA hex color"
                .to_string(),
        ));
    }

    Ok(())
}

fn build_trusted_providers(
    providers: Vec<TrustedProviderConfig>,
) -> Result<HashMap<String, TrustedProviderConfig>, AppError> {
    let mut result = HashMap::new();
    for provider in providers {
        if provider.provider_id.trim().is_empty() {
            return Err(AppError::Config(
                "trusted provider_id must not be empty".to_string(),
            ));
        }
        if provider.provider_id.contains(':') {
            return Err(AppError::Config(format!(
                "trusted provider_id '{}' must not contain ':' because it prefixes local subjects",
                provider.provider_id
            )));
        }
        if result.contains_key(&provider.provider_id) {
            return Err(AppError::Config(format!(
                "duplicate trusted provider_id '{}'",
                provider.provider_id
            )));
        }
        validate_trusted_provider(&provider)?;
        result.insert(provider.provider_id.clone(), provider);
    }
    Ok(result)
}

fn validate_trusted_provider(provider: &TrustedProviderConfig) -> Result<(), AppError> {
    if provider.allowed_signing_algorithms.is_empty() {
        return Err(AppError::Config(format!(
            "trusted provider '{}' allowed_signing_algorithms must not be empty",
            provider.provider_id
        )));
    }
    validate_absolute_url(&provider.issuer, "issuer")?;
    validate_absolute_url(&provider.redirect_uri, "redirect_uri")?;
    if provider.client_id.trim().is_empty() {
        return Err(AppError::Config(format!(
            "trusted provider '{}' client_id must not be empty",
            provider.provider_id
        )));
    }
    if provider.client_secret.is_empty() {
        return Err(AppError::Config(format!(
            "trusted provider '{}' client_secret must not be empty",
            provider.provider_id
        )));
    }
    Ok(())
}

fn validate_reauth_clients(
    clients: &HashMap<String, Client>,
    trusted_providers: &HashMap<String, TrustedProviderConfig>,
) -> Result<(), AppError> {
    for client in clients.values() {
        match (&client.auth_mode, &client.re_auth) {
            (ClientAuthMode::Local, None) => {}
            (ClientAuthMode::Local, Some(_)) => {
                return Err(AppError::Config(format!(
                    "local client '{}' must not define re_auth settings",
                    client.client_id
                )));
            }
            (ClientAuthMode::ReAuth, None) => {
                return Err(AppError::Config(format!(
                    "re-auth client '{}' must define re_auth settings",
                    client.client_id
                )));
            }
            (ClientAuthMode::ReAuth, Some(re_auth)) => {
                if !trusted_providers.contains_key(&re_auth.provider_id) {
                    return Err(AppError::Config(format!(
                        "re-auth client '{}' references unknown provider_id '{}'",
                        client.client_id, re_auth.provider_id
                    )));
                }
                if !re_auth
                    .upstream_scopes
                    .iter()
                    .any(|scope| scope == "openid")
                {
                    return Err(AppError::Config(format!(
                        "re-auth client '{}' upstream_scopes must include 'openid'",
                        client.client_id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_absolute_url(value: &str, field_name: &str) -> Result<(), AppError> {
    let parsed = Url::parse(value).map_err(|err| {
        AppError::Config(format!(
            "trusted provider {field_name} must be a valid URL: {err}"
        ))
    })?;
    if parsed.scheme().is_empty() || parsed.host_str().is_none() {
        return Err(AppError::Config(format!(
            "trusted provider {field_name} must be an absolute URL"
        )));
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: PathBuf) -> Result<T, AppError> {
    let data = fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(AppError::from)
}

fn read_json_value(path: PathBuf) -> Result<Value, AppError> {
    let data = fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(AppError::from)
}

fn read_json_value_optional(path: PathBuf) -> Result<Option<Value>, AppError> {
    match fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data)
            .map(Some)
            .map_err(AppError::from),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AppError::from(error)),
    }
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

#[cfg(test)]
mod tests {
    use super::{ClientAuthMode, ClientConfig, build_clients, validate_reauth_clients};

    #[test]
    fn client_signing_override_is_optional_and_only_accepts_supported_algorithms() {
        let mut value = serde_json::json!({"client_id": "client", "client_secret": "secret"});
        let client: ClientConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(client.signing_algorithm.is_none());
        value["signing_algorithm"] = serde_json::Value::Null;
        let client: ClientConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(client.signing_algorithm.is_none());
        for algorithm in [
            super::SigningAlgorithm::RS256,
            super::SigningAlgorithm::ES256,
            super::SigningAlgorithm::PS256,
        ] {
            value["signing_algorithm"] = serde_json::json!(algorithm);
            let client: ClientConfig = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(
                build_clients(vec![client]).unwrap()["client"].signing_algorithm,
                Some(algorithm)
            );
        }
        for algorithm in ["HS256", "PS384", "none", "rs256"] {
            value["signing_algorithm"] = serde_json::json!(algorithm);
            assert!(serde_json::from_value::<ClientConfig>(value.clone()).is_err());
        }
    }

    #[test]
    fn upstream_signing_algorithms_default_to_rs256_and_require_a_nonempty_supported_list() {
        use super::{SigningAlgorithm, TrustedProviderConfig, validate_trusted_provider};
        let mut config = serde_json::json!({
            "provider_id": "partner",
            "issuer": "https://partner.example.test",
            "client_id": "proxy",
            "client_secret": "secret",
            "redirect_uri": "https://pocket.example.test/reauth/callback/partner"
        });
        let provider: TrustedProviderConfig = serde_json::from_value(config.clone()).unwrap();
        assert_eq!(
            provider.allowed_signing_algorithms,
            vec![SigningAlgorithm::RS256]
        );

        config["allowed_signing_algorithms"] = serde_json::json!(["RS256", "ES256", "PS256"]);
        let provider: TrustedProviderConfig = serde_json::from_value(config.clone()).unwrap();
        validate_trusted_provider(&provider).unwrap();

        config["allowed_signing_algorithms"] = serde_json::json!([]);
        let provider: TrustedProviderConfig = serde_json::from_value(config.clone()).unwrap();
        assert!(
            validate_trusted_provider(&provider)
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );

        for algorithm in ["HS256", "ES384", "none"] {
            config["allowed_signing_algorithms"] = serde_json::json!([algorithm]);
            assert!(serde_json::from_value::<TrustedProviderConfig>(config.clone()).is_err());
        }
    }

    #[test]
    fn client_auth_mode_defaults_to_local() {
        let client: ClientConfig = serde_json::from_str(
            r#"{
                "client_id": "svc-a",
                "client_secret": "supersecret"
            }"#,
        )
        .expect("minimal client config should parse");

        assert_eq!(client.auth_mode, ClientAuthMode::Local);
        assert!(client.re_auth.is_none());
    }

    #[test]
    fn reauth_client_requires_a_known_trusted_provider() {
        let client: ClientConfig = serde_json::from_str(
            r#"{
                "client_id": "svc-reauth",
                "client_secret": "supersecret",
                "auth_mode": "re_auth",
                "re_auth": {
                    "provider_id": "missing-provider",
                    "upstream_scopes": ["openid"]
                }
            }"#,
        )
        .expect("re-auth client config should parse");
        let clients = build_clients(vec![client]).expect("client config should build");

        let error = validate_reauth_clients(&clients, &std::collections::HashMap::new())
            .expect_err("missing provider should fail validation");
        assert!(
            error
                .to_string()
                .contains("unknown provider_id 'missing-provider'")
        );
    }
}
