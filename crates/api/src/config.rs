//! Startup configuration: one TOML file, environment overrides.
//!
//! The server fails fast on invalid configuration (fail closed): missing
//! secrets or malformed values abort startup, never degrade into an open
//! mode.

use std::path::Path;

use serde::Deserialize;

use crate::error::Error;

/// Listen address for the HTTP server.
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
/// Default request body limit (64 KiB).
const DEFAULT_BODY_LIMIT: usize = 64 * 1024;

/// Database backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseKind {
    /// Embedded SQLite (development and H6 embedded mode).
    Sqlite,
    /// Postgres (service deployments).
    Postgres,
}

/// Server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address to listen on (e.g. `127.0.0.1:8080`).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Database backend.
    pub database: DatabaseKind,
    /// Database URL (`sqlite:path/to.db` or `postgres://...`).
    pub database_url: String,
    /// Path to the 32-byte local KMS key file.
    pub kms_key_file: String,
    /// KEK identifier recorded on sealed secrets.
    pub kek_id: String,
    /// Static service key for S2S calls (H3 stepping stone; H6 moves to
    /// per-client keys in the database).
    pub service_key: String,
    /// Max JSON body size in bytes.
    #[serde(default = "default_body_limit")]
    pub body_limit_bytes: usize,
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

fn default_body_limit() -> usize {
    DEFAULT_BODY_LIMIT
}

impl Config {
    /// Loads `path` as TOML, then applies `BANDALL_*` environment overrides.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Config(e.to_string()))?;
        let mut config: Self = toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?;
        config.apply_env();
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self) {
        if let Ok(value) = std::env::var("BANDALL_LISTEN") {
            self.listen = value;
        }
        if let Ok(value) = std::env::var("BANDALL_DATABASE_URL") {
            self.database_url = value;
        }
        if let Ok(value) = std::env::var("BANDALL_KMS_KEY_FILE") {
            self.kms_key_file = value;
        }
        if let Ok(value) = std::env::var("BANDALL_KEK_ID") {
            self.kek_id = value;
        }
        if let Ok(value) = std::env::var("BANDALL_SERVICE_KEY") {
            self.service_key = value;
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.database_url.is_empty() {
            return Err(Error::Config("database_url is empty".to_string()));
        }
        if self.kms_key_file.is_empty() {
            return Err(Error::Config("kms_key_file is empty".to_string()));
        }
        if self.kek_id.is_empty() {
            return Err(Error::Config("kek_id is empty".to_string()));
        }
        if self.service_key.len() < 32 {
            return Err(Error::Config(
                "service_key must be at least 32 characters".to_string(),
            ));
        }
        if self.body_limit_bytes == 0 {
            return Err(Error::Config(
                "body_limit_bytes must be positive".to_string(),
            ));
        }
        Ok(())
    }

    /// Example configuration file for operators.
    #[must_use]
    pub fn example() -> String {
        format!(
            "# BandAll server configuration.\n\
             listen = \"{DEFAULT_LISTEN}\"\n\
             database = \"sqlite\"\n\
             database_url = \"sqlite:bandall.db\"\n\
             kms_key_file = \"/run/secrets/bandall-kek\"\n\
             kek_id = \"kek-1\"\n\
             service_key = \"change-me-to-at-least-32-chars\"\n\
             body_limit_bytes = {DEFAULT_BODY_LIMIT}\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn write_config(body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("bandall-test-{}.toml", std::process::id()));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn rejects_weak_service_key() {
        let path = write_config(
            "database = \"sqlite\"\ndatabase_url = \"sqlite::memory:\"\n\
             kms_key_file = \"/x\"\nkek_id = \"k\"\nservice_key = \"short\"\n",
        );
        let result = Config::load(&path);
        std::fs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn accepts_full_config() {
        let path = write_config(
            "database = \"sqlite\"\ndatabase_url = \"sqlite::memory:\"\n\
             kms_key_file = \"/x\"\nkek_id = \"kek-1\"\n\
             service_key = \"0123456789abcdef0123456789abcdef\"\n",
        );
        let result = Config::load(&path);
        std::fs::remove_file(&path).ok();
        let config = result.unwrap();
        assert_eq!(config.listen, "127.0.0.1:8080");
    }
}
