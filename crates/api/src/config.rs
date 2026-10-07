//! Startup configuration: one TOML file, environment overrides.
//!
//! The server fails fast on invalid configuration (fail closed): missing
//! secrets or malformed values abort startup, never degrade into an open
//! mode.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

/// Failure-tracker backend (ADR-0008).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyBackendKind {
    /// Process-local, single replica (development, embedded mode, tests).
    #[default]
    Memory,
    /// Shared `auth_failures` table: global limits across replicas.
    Database,
}

/// Reverse proxies allowed to set `X-Forwarded-For`: exact IPs or CIDRs.
#[derive(Debug, Default)]
pub struct TrustedProxies {
    nets: Vec<(IpAddr, u8)>,
}

impl TrustedProxies {
    /// Parses entries like `10.0.0.1`, `10.0.0.0/8`, `::1` or `fd00::/8`.
    pub fn parse(values: &[String]) -> Result<Self, Error> {
        let mut nets = Vec::with_capacity(values.len());
        for value in values {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let (addr, prefix) = match value.split_once('/') {
                Some((addr, prefix)) => {
                    let addr = addr.trim().parse::<IpAddr>().map_err(|_| {
                        Error::Config(format!("invalid trusted proxy address: {addr}"))
                    })?;
                    let prefix = prefix.trim().parse::<u8>().map_err(|_| {
                        Error::Config(format!("invalid trusted proxy prefix in {value}"))
                    })?;
                    (addr, prefix)
                }
                None => {
                    let addr = value
                        .parse::<IpAddr>()
                        .map_err(|_| Error::Config(format!("invalid trusted proxy: {value}")))?;
                    let prefix = match addr {
                        IpAddr::V4(_) => 32,
                        IpAddr::V6(_) => 128,
                    };
                    (addr, prefix)
                }
            };
            let max = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return Err(Error::Config(format!(
                    "trusted proxy prefix out of range: {value}"
                )));
            }
            nets.push((addr, prefix));
        }
        Ok(Self { nets })
    }

    /// Whether any proxy is trusted (empty = never honour `X-Forwarded-For`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Whether `addr` falls inside any configured network.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.nets.iter().any(|(net, prefix)| match (net, addr) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                masked_v4(*net, *prefix) == masked_v4(addr, *prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                masked_v6(*net, *prefix) == masked_v6(addr, *prefix)
            }
            _ => false,
        })
    }
}

fn masked_v4(addr: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    u32::from(addr) & mask
}

fn masked_v6(addr: Ipv6Addr, prefix: u8) -> u128 {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    u128::from(addr) & mask
}

/// Rejects a secret file readable by group or others (Unix). Same rule the
/// local KMS applies to its KEK: without it, any local account could read the
/// audit-chain key and forge a log that verifies.
pub fn require_owner_only_file(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| Error::Config(format!("cannot stat {0}: {e}", path.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Error::Config(format!(
                "{0} must not be group- or world-readable (chmod 600)",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        // Non-Unix platforms rely on the deployment to restrict access.
        let _ = path;
    }
    Ok(())
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
    /// Path to the 32-byte audit-chain key file (T4). Kept outside the
    /// database: without it a writer could recompute the whole chain.
    pub audit_key_file: String,
    /// Static service key for S2S calls (H3 stepping stone; H6 moves to
    /// per-client keys in the database).
    pub service_key: String,
    /// Token issuer (`iss` claim).
    #[serde(default = "default_issuer")]
    pub token_issuer: String,
    /// Token audience (`aud` claim).
    #[serde(default = "default_audience")]
    pub token_audience: String,
    /// Directory holding `current.key` (+ `previous.key` in rotation).
    #[serde(default = "default_keys_dir")]
    pub keys_dir: String,
    /// Failure-tracker backend (`memory` or `database`, ADR-0008).
    #[serde(default)]
    pub policy_backend: PolicyBackendKind,
    /// Verification attempts tolerated per factor per window before backoff.
    #[serde(default = "default_policy_max_attempts")]
    pub policy_max_attempts: u32,
    /// Consecutive factor failures triggering temporary lockout.
    #[serde(default = "default_policy_lockout_after")]
    pub policy_lockout_after: u32,
    /// Attempts tolerated per tenant per window (high ceiling: a flood must
    /// never lock a whole tenant, only throttle it).
    #[serde(default = "default_policy_tenant_max_attempts")]
    pub policy_tenant_max_attempts: u32,
    /// Attempts tolerated per client IP per window (high ceiling).
    #[serde(default = "default_policy_ip_max_attempts")]
    pub policy_ip_max_attempts: u32,
    /// Reverse proxies trusted to set `X-Forwarded-For` (IPs or CIDRs).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
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

fn default_issuer() -> String {
    "bandall".to_string()
}

fn default_audience() -> String {
    "bandall".to_string()
}

fn default_keys_dir() -> String {
    "keys".to_string()
}

fn default_policy_max_attempts() -> u32 {
    5
}

fn default_policy_lockout_after() -> u32 {
    10
}

fn default_policy_tenant_max_attempts() -> u32 {
    1_000
}

fn default_policy_ip_max_attempts() -> u32 {
    300
}

impl Config {
    /// Loads `path` as TOML, then applies `BANDALL_*` environment overrides.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Config(e.to_string()))?;
        let mut config: Self = toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?;
        config.apply_env()?;
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self) -> Result<(), Error> {
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
        if let Ok(value) = std::env::var("BANDALL_AUDIT_KEY_FILE") {
            self.audit_key_file = value;
        }
        if let Ok(value) = std::env::var("BANDALL_SERVICE_KEY") {
            self.service_key = value;
        }
        if let Ok(value) = std::env::var("BANDALL_TOKEN_ISSUER") {
            self.token_issuer = value;
        }
        if let Ok(value) = std::env::var("BANDALL_TOKEN_AUDIENCE") {
            self.token_audience = value;
        }
        if let Ok(value) = std::env::var("BANDALL_KEYS_DIR") {
            self.keys_dir = value;
        }
        if let Ok(value) = std::env::var("BANDALL_POLICY_BACKEND") {
            self.policy_backend = match value.trim().to_ascii_lowercase().as_str() {
                "memory" => PolicyBackendKind::Memory,
                "database" => PolicyBackendKind::Database,
                other => {
                    return Err(Error::Config(format!("invalid policy_backend: {other}")));
                }
            };
        }
        if let Ok(value) = std::env::var("BANDALL_POLICY_TENANT_MAX_ATTEMPTS") {
            if let Ok(parsed) = value.parse() {
                self.policy_tenant_max_attempts = parsed;
            }
        }
        if let Ok(value) = std::env::var("BANDALL_POLICY_IP_MAX_ATTEMPTS") {
            if let Ok(parsed) = value.parse() {
                self.policy_ip_max_attempts = parsed;
            }
        }
        if let Ok(value) = std::env::var("BANDALL_POLICY_MAX_ATTEMPTS") {
            if let Ok(parsed) = value.parse() {
                self.policy_max_attempts = parsed;
            }
        }
        if let Ok(value) = std::env::var("BANDALL_POLICY_LOCKOUT_AFTER") {
            if let Ok(parsed) = value.parse() {
                self.policy_lockout_after = parsed;
            }
        }
        if let Ok(value) = std::env::var("BANDALL_TRUSTED_PROXIES") {
            self.trusted_proxies = value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect();
        }
        Ok(())
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
        // Mandatory: without the key the chain falls back to the legacy
        // unkeyed hash, which anyone with write access can recompute.
        if self.audit_key_file.is_empty() {
            return Err(Error::Config("audit_key_file is empty".to_string()));
        }
        if self.service_key.len() < 32 {
            return Err(Error::Config(
                "service_key must be at least 32 characters".to_string(),
            ));
        }
        if self.token_issuer.is_empty() {
            return Err(Error::Config("token_issuer is empty".to_string()));
        }
        if self.token_audience.is_empty() {
            return Err(Error::Config("token_audience is empty".to_string()));
        }
        if self.keys_dir.is_empty() {
            return Err(Error::Config("keys_dir is empty".to_string()));
        }
        if self.body_limit_bytes == 0 {
            return Err(Error::Config(
                "body_limit_bytes must be positive".to_string(),
            ));
        }
        if self.policy_max_attempts == 0
            || self.policy_tenant_max_attempts == 0
            || self.policy_ip_max_attempts == 0
        {
            return Err(Error::Config(
                "policy attempt limits must be positive".to_string(),
            ));
        }
        // Fail fast on a malformed proxy list instead of trusting nobody.
        TrustedProxies::parse(&self.trusted_proxies)?;
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
             audit_key_file = \"/run/secrets/bandall-audit-key\"\n\
             service_key = \"change-me-to-at-least-32-chars\"\n\
             token_issuer = \"bandall\"\n\
             token_audience = \"bandall\"\n\
             keys_dir = \"keys\"\n\
             policy_backend = \"memory\"\n\
             policy_max_attempts = 5\n\
             policy_lockout_after = 10\n\
             policy_tenant_max_attempts = 1000\n\
             policy_ip_max_attempts = 300\n\
             trusted_proxies = []\n\
             body_limit_bytes = {DEFAULT_BODY_LIMIT}\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, PolicyBackendKind, TrustedProxies};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique per call: tests run in parallel and would otherwise share (and
    /// delete) each other's file.
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn write_config(body: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bandall-config-test-{}-{id}.toml",
            std::process::id()
        ));
        std::fs::write(&path, body).unwrap();
        path
    }

    /// Writes `len` bytes of test key material to a unique temp file with
    /// `mode` permissions, and returns the path.
    fn audit_key_file(tag: &str, len: usize, mode: u32) -> std::path::PathBuf {
        use std::io::Write;
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bandall-audit-key-{tag}-{}-{id}.bin",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&vec![7u8; len]).unwrap();
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
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
             kms_key_file = \"/x\"\nkek_id = \"kek-1\"\naudit_key_file = \"/run/secrets/bandall-audit-key\"\n\
             service_key = \"0123456789abcdef0123456789abcdef\"\n",
        );
        let result = Config::load(&path);
        std::fs::remove_file(&path).ok();
        let config = result.unwrap();
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert_eq!(config.policy_backend, PolicyBackendKind::Memory);
        assert_eq!(config.policy_tenant_max_attempts, 1_000);
        assert!(config.trusted_proxies.is_empty());
    }

    #[test]
    fn rejects_invalid_trusted_proxy() {
        let path = write_config(
            "database = \"sqlite\"\ndatabase_url = \"sqlite::memory:\"\n\
             kms_key_file = \"/x\"\nkek_id = \"kek-1\"\naudit_key_file = \"/run/secrets/bandall-audit-key\"\n\
             service_key = \"0123456789abcdef0123456789abcdef\"\n\
             trusted_proxies = [\"not-an-ip\"]\n",
        );
        let result = Config::load(&path);
        std::fs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn requires_an_audit_key_file() {
        // Without a key the chain falls back to the legacy unkeyed hash,
        // which anyone with write access can recompute. Fail at startup
        // instead of silently downgrading the audit log.
        let path = write_config(
            "database = \"sqlite\"\ndatabase_url = \"sqlite::memory:\"\n\
             kms_key_file = \"/x\"\nkek_id = \"kek-1\"\n\
             service_key = \"0123456789abcdef0123456789abcdef\"\n",
        );
        let result = Config::load(&path);
        std::fs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_a_world_readable_audit_key() {
        #[cfg(unix)]
        {
            let path = audit_key_file("bad", 32, 0o644);
            let result = crate::audit::AuditChain::from_file(&path);
            std::fs::remove_file(&path).ok();
            assert!(result.is_err(), "0644 audit key must be refused");
        }
    }

    #[test]
    fn accepts_an_owner_only_audit_key_file() {
        #[cfg(unix)]
        {
            let path = audit_key_file("ok", 32, 0o600);
            assert!(crate::audit::AuditChain::from_file(&path).is_ok());
            std::fs::remove_file(&path).ok();
        }
    }

    #[test]
    fn rejects_a_short_audit_key() {
        #[cfg(unix)]
        {
            let path = audit_key_file("short", 16, 0o600);
            assert!(crate::audit::AuditChain::from_file(&path).is_err());
            std::fs::remove_file(&path).ok();
        }
    }

    #[test]
    fn trusted_proxies_match_exact_and_cidr() {
        let proxies = TrustedProxies::parse(&[
            "10.0.0.1".to_string(),
            "192.168.0.0/16".to_string(),
            "fd00::/8".to_string(),
        ])
        .unwrap();
        assert!(proxies.contains("10.0.0.1".parse().unwrap()));
        assert!(proxies.contains("192.168.44.9".parse().unwrap()));
        assert!(proxies.contains("fd00::1".parse().unwrap()));
        assert!(!proxies.contains("10.0.0.2".parse().unwrap()));
        assert!(!proxies.contains("192.169.0.1".parse().unwrap()));
        // Family mismatch never matches.
        assert!(!proxies.contains("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!proxies.is_empty());
        assert!(TrustedProxies::default().is_empty());
    }
}
