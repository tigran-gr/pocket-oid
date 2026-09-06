use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, anyhow};
use argon2::{
    Argon2, Params,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

use crate::error::AppError;

const SQLITE_SCHEMA_VERSION: i64 = 1;
const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    username      TEXT NOT NULL UNIQUE CHECK (length(username) > 0),
    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum UsersConfig {
    File {
        #[serde(default)]
        users: Vec<UserConfig>,
    },
    Sqlite {
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub password_plain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    credential: PasswordCredential,
}

#[derive(Debug, Clone)]
enum PasswordCredential {
    Argon2id { phc: String },
    Sha256 { hex: String },
    Plain { value: String },
}

#[derive(Debug, Clone)]
pub struct UserStore {
    backend: UserStoreBackend,
    dummy_credential: PasswordCredential,
    password_verification_limit: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
enum UserStoreBackend {
    File(Arc<HashMap<String, User>>),
    Sqlite(Arc<SqliteUserStore>),
}

#[derive(Debug)]
struct SqliteUserStore {
    connection: Mutex<Connection>,
    path: PathBuf,
}

impl UserStore {
    pub fn load(config: UsersConfig, config_root: &Path) -> Result<Self, AppError> {
        let dummy_credential = create_dummy_credential()?;
        let backend = match config {
            UsersConfig::File { users } => {
                let users = build_file_users(users)?;
                if users.is_empty() {
                    return Err(AppError::Config("no users configured".into()));
                }
                UserStoreBackend::File(Arc::new(users))
            }
            UsersConfig::Sqlite { path } => {
                let store = SqliteUserStore::open(config_root, path)?;
                UserStoreBackend::Sqlite(Arc::new(store))
            }
        };
        Ok(Self {
            backend,
            dummy_credential,
            password_verification_limit: Arc::new(Semaphore::new(password_verification_limit())),
        })
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<User>> {
        let permit = self
            .password_verification_limit
            .clone()
            .acquire_owned()
            .await
            .context("password verification concurrency limiter closed")?;
        let store = self.clone();
        let username = username.to_string();
        let password = password.to_string();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.authenticate_blocking(&username, &password)
        })
        .await
        .context("password verification task failed")?
    }

    fn authenticate_blocking(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<User>> {
        let user = match &self.backend {
            UserStoreBackend::File(users) => users.get(username).cloned(),
            UserStoreBackend::Sqlite(store) => store.find_enabled_user(username)?,
        };
        let valid = user
            .as_ref()
            .map(|user| &user.credential)
            .unwrap_or(&self.dummy_credential)
            .verify_password(password);
        Ok(if valid { user } else { None })
    }
}

impl SqliteUserStore {
    fn open(config_root: &Path, configured_path: PathBuf) -> Result<Self, AppError> {
        if configured_path.as_os_str().is_empty() {
            return Err(AppError::Config(
                "sqlite users path must not be empty".to_string(),
            ));
        }
        let path = if configured_path.is_absolute() {
            configured_path
        } else {
            config_root.join(configured_path)
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::Config(format!(
                    "failed to create sqlite users directory '{}': {error}",
                    parent.display()
                ))
            })?;
        }
        let mut connection = Connection::open(&path).map_err(|error| {
            AppError::Config(format!(
                "failed to open sqlite users database '{}': {error}",
                path.display()
            ))
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| sqlite_config_error(&path, error))?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(|error| sqlite_config_error(&path, error))?;
        initialize_schema(&mut connection, &path)?;
        validate_sqlite_users(&connection, &path)?;
        Ok(Self {
            connection: Mutex::new(connection),
            path,
        })
    }

    fn find_enabled_user(&self, username: &str) -> anyhow::Result<Option<User>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow!("sqlite users database lock is poisoned"))?;
        let row = connection
            .query_row(
                "SELECT id, username, password_hash FROM users WHERE username = ?1 AND enabled = 1",
                params![username],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .with_context(|| {
                format!(
                    "failed to query sqlite users database '{}'",
                    self.path.display()
                )
            })?;
        drop(connection);
        row.map(|(id, username, password_hash)| {
            sqlite_user(id, username, password_hash).map_err(anyhow::Error::new)
        })
        .transpose()
    }
}

impl PasswordCredential {
    fn verify_password(&self, password: &str) -> bool {
        match self {
            Self::Argon2id { phc } => PasswordHash::new(phc).is_ok_and(|parsed| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            }),
            Self::Sha256 { hex } => constant_time_eq(hex, &sha256_hex(password)),
            Self::Plain { value } => constant_time_eq(value, password),
        }
    }
}

fn initialize_schema(connection: &mut Connection, path: &Path) -> Result<(), AppError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| sqlite_config_error(path, error))?;
    match version {
        0 => {
            let transaction = connection
                .transaction()
                .map_err(|error| sqlite_config_error(path, error))?;
            transaction
                .execute_batch(SQLITE_SCHEMA)
                .map_err(|error| sqlite_config_error(path, error))?;
            validate_sqlite_schema(&transaction, path)?;
            transaction
                .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
                .map_err(|error| sqlite_config_error(path, error))?;
            transaction
                .commit()
                .map_err(|error| sqlite_config_error(path, error))?;
        }
        SQLITE_SCHEMA_VERSION => validate_sqlite_schema(connection, path)?,
        other => {
            return Err(AppError::Config(format!(
                "sqlite users database '{}' has unsupported schema version {other}; supported version: {SQLITE_SCHEMA_VERSION}",
                path.display()
            )));
        }
    }

    Ok(())
}

fn validate_sqlite_schema(connection: &Connection, path: &Path) -> Result<(), AppError> {
    connection
        .prepare("SELECT id, username, password_hash, enabled, created_at, updated_at FROM users LIMIT 0")
        .map_err(|error| sqlite_config_error(path, error))?;
    Ok(())
}

fn validate_sqlite_users(connection: &Connection, path: &Path) -> Result<(), AppError> {
    let mut statement = connection
        .prepare("SELECT id, username, password_hash, enabled FROM users")
        .map_err(|error| sqlite_config_error(path, error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })
        .map_err(|error| sqlite_config_error(path, error))?;
    let mut enabled_users = 0_usize;
    for row in rows {
        let (id, username, password_hash, enabled) =
            row.map_err(|error| sqlite_config_error(path, error))?;
        sqlite_user(id, username, password_hash)?;
        if enabled {
            enabled_users += 1;
        }
    }
    if enabled_users == 0 {
        return Err(AppError::Config(format!(
            "sqlite users database '{}' contains no enabled users",
            path.display()
        )));
    }
    Ok(())
}

fn sqlite_user(id: String, username: String, password_hash: String) -> Result<User, AppError> {
    if id.trim().is_empty() {
        return Err(AppError::Config(
            "sqlite user id must not be empty".to_string(),
        ));
    }
    if username.trim().is_empty() {
        return Err(AppError::Config(
            "sqlite username must not be empty".to_string(),
        ));
    }
    let credential = parse_argon2id_hash(&username, &password_hash)?;
    Ok(User {
        id,
        username,
        credential,
    })
}

fn build_file_users(users: Vec<UserConfig>) -> Result<HashMap<String, User>, AppError> {
    let mut result = HashMap::new();
    let mut ids = std::collections::HashSet::new();
    for user in users {
        if user.id.trim().is_empty() {
            return Err(AppError::Config(
                "file user id must not be empty".to_string(),
            ));
        }
        if user.username.trim().is_empty() {
            return Err(AppError::Config(
                "file username must not be empty".to_string(),
            ));
        }
        if !ids.insert(user.id.clone()) {
            return Err(AppError::Config(format!(
                "duplicate file user id '{}'",
                user.id
            )));
        }
        if result.contains_key(&user.username) {
            return Err(AppError::Config(format!(
                "duplicate file username '{}'",
                user.username
            )));
        }
        let credential = file_user_credential(&user)?;
        result.insert(
            user.username.clone(),
            User {
                id: user.id,
                username: user.username,
                credential,
            },
        );
    }
    Ok(result)
}

fn file_user_credential(user: &UserConfig) -> Result<PasswordCredential, AppError> {
    match (&user.password_hash, &user.password_plain) {
        (Some(_), Some(_)) => Err(AppError::Config(format!(
            "user '{}' must set only one of password_hash or password_plain",
            user.username
        ))),
        (Some(hash), None) if hash.starts_with("$argon2id$") => {
            parse_argon2id_hash(&user.username, hash)
        }
        (Some(hash), None) => parse_legacy_sha256_hash(&user.username, hash),
        (None, Some(password)) => Ok(PasswordCredential::Plain {
            value: password.clone(),
        }),
        (None, None) => Err(AppError::Config(format!(
            "user '{}' must set password_hash or password_plain",
            user.username
        ))),
    }
}

fn parse_argon2id_hash(
    username: &str,
    password_hash: &str,
) -> Result<PasswordCredential, AppError> {
    let parsed = PasswordHash::new(password_hash).map_err(|error| {
        AppError::Config(format!(
            "user '{username}' has an invalid Argon2id PHC password hash: {error}"
        ))
    })?;
    if parsed.algorithm.as_str() != "argon2id" || parsed.salt.is_none() || parsed.hash.is_none() {
        return Err(AppError::Config(format!(
            "user '{username}' password_hash must be a complete Argon2id PHC string"
        )));
    }
    if parsed.version != Some(19) {
        return Err(AppError::Config(format!(
            "user '{username}' password_hash must use Argon2 version 19"
        )));
    }
    let parameters = Params::try_from(&parsed).map_err(|error| {
        AppError::Config(format!(
            "user '{username}' has invalid Argon2id parameters: {error}"
        ))
    })?;
    if parameters.m_cost() < Params::DEFAULT_M_COST
        || parameters.t_cost() < Params::DEFAULT_T_COST
        || parsed
            .hash
            .is_none_or(|output| output.len() < Params::DEFAULT_OUTPUT_LEN)
    {
        return Err(AppError::Config(format!(
            "user '{username}' Argon2id hash must use at least m={}, t={}, and a {}-byte output",
            Params::DEFAULT_M_COST,
            Params::DEFAULT_T_COST,
            Params::DEFAULT_OUTPUT_LEN
        )));
    }
    Ok(PasswordCredential::Argon2id {
        phc: password_hash.to_string(),
    })
}

fn parse_legacy_sha256_hash(
    username: &str,
    password_hash: &str,
) -> Result<PasswordCredential, AppError> {
    let Some(hex) = password_hash.strip_prefix("sha256:") else {
        return Err(AppError::Config(format!(
            "user '{username}' password_hash must use an Argon2id PHC string or legacy sha256:<hex>"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Config(format!(
            "user '{username}' password_hash must contain a 64-character sha256 hex digest"
        )));
    }
    Ok(PasswordCredential::Sha256 {
        hex: hex.to_ascii_lowercase(),
    })
}

fn create_dummy_credential() -> Result<PasswordCredential, AppError> {
    let salt = SaltString::encode_b64(b"pocket-oid-dummy-salt").map_err(|error| {
        AppError::Config(format!(
            "failed to create password verification salt: {error}"
        ))
    })?;
    let phc = Argon2::default()
        .hash_password(b"not-a-user-password", &salt)
        .map_err(|error| {
            AppError::Config(format!(
                "failed to initialize password verification: {error}"
            ))
        })?
        .to_string();
    Ok(PasswordCredential::Argon2id { phc })
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn sqlite_config_error(path: &Path, error: rusqlite::Error) -> AppError {
    AppError::Config(format!(
        "sqlite users database '{}' error: {error}",
        path.display()
    ))
}

fn password_verification_limit() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1)
        .min(8)
}

#[cfg(test)]
mod tests {
    use super::{SQLITE_SCHEMA_VERSION, UserConfig, UserStore, UsersConfig, initialize_schema};
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString},
    };
    use rusqlite::{Connection, params};
    use std::{fs, path::Path};
    use uuid::Uuid;

    fn argon2id_hash(password: &str) -> String {
        let salt = SaltString::encode_b64(b"unique-test-salt").unwrap();
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    fn temporary_root() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("pocket-oid-users-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn create_sqlite_user(path: &Path, username: &str, password_hash: &str) {
        let mut connection = Connection::open(path).unwrap();
        initialize_schema(&mut connection, path).unwrap();
        connection
            .execute(
                "INSERT INTO users (id, username, password_hash) VALUES (?1, ?2, ?3)",
                params![format!("user-{username}"), username, password_hash],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn authenticates_argon2id_file_user() {
        let store = UserStore::load(
            UsersConfig::File {
                users: vec![UserConfig {
                    id: "user-alice".to_string(),
                    username: "alice".to_string(),
                    password_hash: Some(argon2id_hash("password123")),
                    password_plain: None,
                }],
            },
            Path::new("."),
        )
        .unwrap();

        assert!(
            store
                .authenticate("alice", "password123")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .authenticate("alice", "wrong")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn legacy_file_password_formats_remain_supported() {
        let store = UserStore::load(
            UsersConfig::File {
                users: vec![
                    UserConfig {
                        id: "user-alice".to_string(),
                        username: "alice".to_string(),
                        password_hash: Some(
                            "sha256:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
                                .to_string(),
                        ),
                        password_plain: None,
                    },
                    UserConfig {
                        id: "user-bob".to_string(),
                        username: "bob".to_string(),
                        password_hash: None,
                        password_plain: Some("password456".to_string()),
                    },
                ],
            },
            Path::new("."),
        )
        .unwrap();

        assert!(
            store
                .authenticate("alice", "password123")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .authenticate("bob", "password456")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn users_config_selects_a_sqlite_provider_with_a_path() {
        let config: UsersConfig =
            serde_json::from_str(r#"{"provider":"sqlite","path":"data/users.sqlite3"}"#).unwrap();
        assert!(matches!(
            config,
            UsersConfig::Sqlite { path } if path == Path::new("data/users.sqlite3")
        ));
    }

    #[test]
    fn rejects_legacy_password_key_without_supported_password_fields() {
        let config: UsersConfig = serde_json::from_str(
            r#"{
                "provider": "file",
                "users": [
                    {"id":"user-alice","username":"alice","password":"password123"}
                ]
            }"#,
        )
        .unwrap();
        let error = UserStore::load(config, Path::new("."))
            .expect_err("legacy password key should be rejected");
        assert!(
            error
                .to_string()
                .contains("must set password_hash or password_plain")
        );
    }

    #[tokio::test]
    async fn sqlite_path_is_relative_to_config_and_changes_are_visible_without_reload() {
        let root = temporary_root();
        let database_path = root.join("data/users.sqlite3");
        fs::create_dir_all(database_path.parent().unwrap()).unwrap();
        create_sqlite_user(&database_path, "alice", &argon2id_hash("password123"));
        let store = UserStore::load(
            UsersConfig::Sqlite {
                path: "data/users.sqlite3".into(),
            },
            &root,
        )
        .unwrap();

        assert!(
            store
                .authenticate("alice", "password123")
                .await
                .unwrap()
                .is_some()
        );
        create_sqlite_user(&database_path, "bob", &argon2id_hash("password456"));
        assert!(
            store
                .authenticate("bob", "password456")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .authenticate("missing", "password456")
                .await
                .unwrap()
                .is_none()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_requires_argon2id_password_hashes() {
        let root = temporary_root();
        let database_path = root.join("users.sqlite3");
        create_sqlite_user(
            &database_path,
            "alice",
            "sha256:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
        );
        let error = UserStore::load(
            UsersConfig::Sqlite {
                path: "users.sqlite3".into(),
            },
            &root,
        )
        .expect_err("legacy SHA-256 should be rejected for sqlite users");

        assert!(error.to_string().contains("Argon2id PHC"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_rejects_unknown_schema_versions() {
        let root = temporary_root();
        let database_path = root.join("users.sqlite3");
        let connection = Connection::open(&database_path).unwrap();
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION + 1)
            .unwrap();
        drop(connection);

        let error = UserStore::load(
            UsersConfig::Sqlite {
                path: "users.sqlite3".into(),
            },
            &root,
        )
        .expect_err("unknown schema version should be rejected");
        assert!(error.to_string().contains("unsupported schema version"));
        fs::remove_dir_all(root).unwrap();
    }
}
