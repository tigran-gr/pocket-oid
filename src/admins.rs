use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};
use serde::Deserialize;
use uuid::Uuid;

const SQLITE_SCHEMA_VERSION: i64 = 2;
const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admins (
    id            TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    username      TEXT NOT NULL UNIQUE CHECK (length(username) > 0),
    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
    credential_version INTEGER NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum AdminsConfig {
    Sqlite { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRecord {
    pub id: String,
    pub username: String,
    pub enabled: bool,
    pub created_at: String,
    pub credential_version: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordChangeResult {
    Changed,
    IncorrectCurrentPassword,
    PasswordUnchanged,
    AccountUnavailable,
    CredentialsChanged,
}

#[derive(Debug)]
pub struct AdminStore {
    connection: Mutex<Connection>,
    path: PathBuf,
    dummy_hash: String,
}

impl AdminStore {
    pub fn load_from_directory(config_root: &Path) -> anyhow::Result<Self> {
        let config_path = config_root.join("admins.json");
        let data = fs::read_to_string(&config_path).with_context(|| {
            format!(
                "failed to read administrator configuration '{}'",
                config_path.display()
            )
        })?;
        let config: AdminsConfig = serde_json::from_str(&data).with_context(|| {
            format!(
                "failed to parse administrator configuration '{}'",
                config_path.display()
            )
        })?;
        Self::open(config, config_root)
    }

    pub fn open(config: AdminsConfig, config_root: &Path) -> anyhow::Result<Self> {
        let AdminsConfig::Sqlite {
            path: configured_path,
        } = config;
        if configured_path.as_os_str().is_empty() {
            bail!("administrator SQLite path must not be empty");
        }
        let path = if configured_path.is_absolute() {
            configured_path
        } else {
            config_root.join(configured_path)
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create administrator database directory '{}'",
                    parent.display()
                )
            })?;
        }

        let mut connection = Connection::open(&path).with_context(|| {
            format!(
                "failed to open administrator SQLite database '{}'",
                path.display()
            )
        })?;
        secure_database_file(&path)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .with_context(|| format!("failed to configure '{}'", path.display()))?;
        initialize_schema(&mut connection, &path)?;

        Ok(Self {
            connection: Mutex::new(connection),
            path,
            dummy_hash: hash_password("not-an-administrator-password")?,
        })
    }

    /// Verify outside the connection lock; callers on async paths must offload this work.
    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<AdminRecord>> {
        let row = {
            let connection = self
                .connection
                .lock()
                .map_err(|_| anyhow!("administrator database lock is poisoned"))?;
            connection.query_row(
                "SELECT id, username, enabled, created_at, credential_version, password_hash FROM admins WHERE username = ?1",
                [username],
                |row| Ok((admin_from_row(row)?, row.get::<_, String>(5)?)),
            ).optional()?
        };
        let hash = row
            .as_ref()
            .filter(|(admin, _)| admin.enabled)
            .map(|(_, hash)| hash.as_str())
            .unwrap_or(&self.dummy_hash);
        let valid = PasswordHash::new(hash).is_ok_and(|parsed| {
            parsed.algorithm.as_str() == "argon2id"
                && Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
        });
        Ok(row
            .filter(|(admin, _)| valid && admin.enabled)
            .map(|(admin, _)| admin))
    }

    pub fn enabled_admin(&self, id: &str) -> anyhow::Result<Option<AdminRecord>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow!("administrator database lock is poisoned"))?;
        Ok(connection.query_row(
            "SELECT id, username, enabled, created_at, credential_version FROM admins WHERE id = ?1 AND enabled = 1",
            [id], admin_from_row,
        ).optional()?)
    }

    pub fn create(&self, username: &str, password: &str) -> anyhow::Result<AdminRecord> {
        validate_username(username)?;
        validate_password(password)?;
        let password_hash = hash_password(password)?;
        let id = Uuid::new_v4().to_string();
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow!("administrator database lock is poisoned"))?;
        match connection.execute(
            "INSERT INTO admins (id, username, password_hash) VALUES (?1, ?2, ?3)",
            params![id, username, password_hash],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == ErrorCode::ConstraintViolation =>
            {
                bail!("administrator '{username}' already exists");
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create administrator in '{}'",
                        self.path.display()
                    )
                });
            }
        }

        connection
            .query_row(
                "SELECT id, username, enabled, created_at, credential_version FROM admins WHERE id = ?1",
                params![id],
                admin_from_row,
            )
            .with_context(|| {
                format!(
                    "failed to read created administrator from '{}'",
                    self.path.display()
                )
            })
    }

    pub fn list(&self) -> anyhow::Result<Vec<AdminRecord>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow!("administrator database lock is poisoned"))?;
        let mut statement = connection
            .prepare(
                "SELECT id, username, enabled, created_at, credential_version FROM admins ORDER BY username COLLATE NOCASE, username",
            )
            .with_context(|| {
                format!(
                    "failed to query administrator database '{}'",
                    self.path.display()
                )
            })?;
        let rows = statement.query_map([], admin_from_row).with_context(|| {
            format!(
                "failed to query administrator database '{}'",
                self.path.display()
            )
        })?;
        rows.collect::<Result<Vec<_>, _>>().with_context(|| {
            format!(
                "failed to read administrator database '{}'",
                self.path.display()
            )
        })
    }

    /// Verify and replace one administrator's password.
    ///
    /// Argon2 work happens outside the connection lock. The final conditional
    /// update makes a concurrent credential change win at most once.
    pub fn change_password(
        &self,
        admin_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> anyhow::Result<PasswordChangeResult> {
        validate_password(new_password)?;
        let credentials = {
            let connection = self
                .connection
                .lock()
                .map_err(|_| anyhow!("administrator database lock is poisoned"))?;
            connection
                .query_row(
                    "SELECT password_hash, credential_version FROM admins WHERE id = ?1 AND enabled = 1",
                    [admin_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?
        };
        let Some((current_hash, credential_version)) = credentials else {
            return Ok(PasswordChangeResult::AccountUnavailable);
        };
        let valid = PasswordHash::new(&current_hash).is_ok_and(|parsed| {
            parsed.algorithm.as_str() == "argon2id"
                && Argon2::default()
                    .verify_password(current_password.as_bytes(), &parsed)
                    .is_ok()
        });
        if !valid {
            return Ok(PasswordChangeResult::IncorrectCurrentPassword);
        }
        if current_password == new_password {
            return Ok(PasswordChangeResult::PasswordUnchanged);
        }

        let new_hash = hash_password(new_password)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow!("administrator database lock is poisoned"))?;
        let changed = connection
            .execute(
                "UPDATE admins
                 SET password_hash = ?1, credential_version = credential_version + 1,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?2 AND enabled = 1 AND credential_version = ?3 AND password_hash = ?4",
                params![new_hash, admin_id, credential_version, current_hash],
            )
            .with_context(|| {
                format!(
                    "failed to change administrator password in '{}'",
                    self.path.display()
                )
            })?;
        Ok(if changed == 1 {
            PasswordChangeResult::Changed
        } else {
            PasswordChangeResult::CredentialsChanged
        })
    }
}

fn initialize_schema(connection: &mut Connection, path: &Path) -> anyhow::Result<()> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .with_context(|| format!("failed to inspect '{}'", path.display()))?;
    match version {
        0 => {
            let transaction = connection
                .transaction()
                .with_context(|| format!("failed to initialize '{}'", path.display()))?;
            transaction
                .execute_batch(SQLITE_SCHEMA)
                .with_context(|| format!("failed to initialize '{}'", path.display()))?;
            validate_schema(&transaction, path)?;
            transaction
                .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
                .with_context(|| format!("failed to initialize '{}'", path.display()))?;
            transaction
                .commit()
                .with_context(|| format!("failed to initialize '{}'", path.display()))?;
        }
        1 => {
            let transaction = connection
                .transaction()
                .with_context(|| format!("failed to migrate '{}'", path.display()))?;
            transaction
                .execute_batch(
                    "ALTER TABLE admins ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 1 CHECK (credential_version > 0);",
                )
                .with_context(|| format!("failed to migrate '{}'", path.display()))?;
            validate_schema(&transaction, path)?;
            transaction
                .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
                .with_context(|| format!("failed to migrate '{}'", path.display()))?;
            transaction
                .commit()
                .with_context(|| format!("failed to migrate '{}'", path.display()))?;
        }
        SQLITE_SCHEMA_VERSION => validate_schema(connection, path)?,
        other => bail!(
            "administrator database '{}' has unsupported schema version {other}; supported version: {SQLITE_SCHEMA_VERSION}",
            path.display()
        ),
    }
    Ok(())
}

fn validate_schema(connection: &Connection, path: &Path) -> anyhow::Result<()> {
    connection
        .prepare(
            "SELECT id, username, password_hash, enabled, created_at, updated_at, credential_version FROM admins LIMIT 0",
        )
        .with_context(|| {
            format!(
                "administrator database '{}' has an invalid schema",
                path.display()
            )
        })?;
    Ok(())
}

fn admin_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AdminRecord> {
    Ok(AdminRecord {
        id: row.get(0)?,
        username: row.get(1)?,
        enabled: row.get(2)?,
        created_at: row.get(3)?,
        credential_version: row.get(4)?,
    })
}

fn validate_username(username: &str) -> anyhow::Result<()> {
    if username.trim().is_empty() {
        bail!("administrator username must not be empty");
    }
    if username != username.trim() {
        bail!("administrator username must not start or end with whitespace");
    }
    if username.chars().any(char::is_control) {
        bail!("administrator username must not contain control characters");
    }
    if username.chars().count() > 128 {
        bail!("administrator username must not exceed 128 characters");
    }
    Ok(())
}

fn validate_password(password: &str) -> anyhow::Result<()> {
    if password.is_empty() {
        bail!("administrator password must not be empty");
    }
    Ok(())
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let mut salt_bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut salt_bytes)
        .map_err(|_| anyhow!("failed to generate a password salt"))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|error| anyhow!("failed to encode password salt: {error}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow!("failed to hash administrator password: {error}"))
}

#[cfg(unix)]
fn secure_database_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
        format!(
            "failed to restrict administrator database permissions for '{}'",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn secure_database_file(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AdminStore, AdminsConfig, PasswordChangeResult, SQLITE_SCHEMA_VERSION, hash_password,
    };
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    use rusqlite::Connection;
    use std::{fs, path::Path};
    use uuid::Uuid;

    fn temporary_root() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("pocket-oid-admins-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn open_store(root: &Path) -> AdminStore {
        AdminStore::open(
            AdminsConfig::Sqlite {
                path: "data/admins.sqlite3".into(),
            },
            root,
        )
        .unwrap()
    }

    #[test]
    fn creates_and_lists_administrators_with_hashed_passwords() {
        let root = temporary_root();
        let store = open_store(&root);

        let created = store
            .create("alice", "correct horse battery staple")
            .unwrap();
        assert_eq!(created.username, "alice");
        assert!(created.enabled);
        assert_eq!(store.list().unwrap(), vec![created]);

        let connection = Connection::open(root.join("data/admins.sqlite3")).unwrap();
        let password_hash: String = connection
            .query_row(
                "SELECT password_hash FROM admins WHERE username = 'alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(password_hash, "correct horse battery staple");
        let parsed = PasswordHash::new(&password_hash).unwrap();
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert!(
            Argon2::default()
                .verify_password(b"correct horse battery staple", &parsed)
                .is_ok()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_duplicate_administrator_names() {
        let root = temporary_root();
        let store = open_store(&root);
        store.create("alice", "first password").unwrap();

        let error = store
            .create("alice", "second password")
            .expect_err("duplicate username should be rejected");
        assert!(error.to_string().contains("already exists"));
        assert_eq!(store.list().unwrap().len(), 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_store_lists_no_administrators() {
        let root = temporary_root();
        let store = open_store(&root);
        assert!(store.list().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unknown_schema_versions() {
        let root = temporary_root();
        let database_path = root.join("admins.sqlite3");
        let connection = Connection::open(&database_path).unwrap();
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION + 1)
            .unwrap();
        drop(connection);

        let error = AdminStore::open(
            AdminsConfig::Sqlite {
                path: "admins.sqlite3".into(),
            },
            &root,
        )
        .expect_err("unknown schema version should be rejected");
        assert!(error.to_string().contains("unsupported schema version"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migrates_existing_administrators_and_changes_password_atomically() {
        let root = temporary_root();
        let database_path = root.join("admins.sqlite3");
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE admins (
                    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
                    username TEXT NOT NULL UNIQUE CHECK (length(username) > 0),
                    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                PRAGMA user_version = 1;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO admins (id, username, password_hash, updated_at)
                 VALUES ('admin-1', 'alice', ?1, '2000-01-01 00:00:00')",
                [hash_password("old password").unwrap()],
            )
            .unwrap();
        drop(connection);

        let store = AdminStore::open(
            AdminsConfig::Sqlite {
                path: "admins.sqlite3".into(),
            },
            &root,
        )
        .unwrap();
        let migrated = store.enabled_admin("admin-1").unwrap().unwrap();
        assert_eq!(migrated.credential_version, 1);
        assert_eq!(
            store
                .change_password("admin-1", "wrong password", "new password")
                .unwrap(),
            PasswordChangeResult::IncorrectCurrentPassword
        );
        assert_eq!(
            store
                .change_password("admin-1", "old password", "old password")
                .unwrap(),
            PasswordChangeResult::PasswordUnchanged
        );
        assert_eq!(
            store
                .change_password("admin-1", "old password", "new password")
                .unwrap(),
            PasswordChangeResult::Changed
        );
        assert!(
            store
                .authenticate("alice", "old password")
                .unwrap()
                .is_none()
        );
        let changed = store
            .authenticate("alice", "new password")
            .unwrap()
            .unwrap();
        assert_eq!(changed.credential_version, 2);

        let connection = Connection::open(&database_path).unwrap();
        let (version, updated_at): (i64, String) = connection
            .query_row(
                "SELECT credential_version, updated_at FROM admins WHERE id = 'admin-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, 2);
        assert_ne!(updated_at, "2000-01-01 00:00:00");
        let schema_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version, SQLITE_SCHEMA_VERSION);

        fs::remove_dir_all(root).unwrap();
    }
}
