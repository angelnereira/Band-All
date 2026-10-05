//! `bandall` binary: server and maintenance commands.
//!
//! The distroless-era healthcheck probes through this binary
//! (`bandall healthcheck`); with the current slim runtime the same subcommand
//! backs the Docker `HEALTHCHECK`.
#![forbid(unsafe_code)]
// This is the one binary that is supposed to talk to the operator.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::trivial_numeric_casts
    )
)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// BandAll security service.
#[derive(Debug, Parser)]
#[command(name = "bandall", version)]
struct Cli {
    /// Subcommand. Defaults to `serve` when omitted for container use.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Runs the HTTP server (default).
    Serve {
        /// Configuration file path.
        #[arg(long, env = "BANDALL_CONFIG", default_value = "bandall.toml")]
        config: PathBuf,
    },
    /// Runs pending database migrations and exits.
    Migrate {
        /// Configuration file path.
        #[arg(long, env = "BANDALL_CONFIG", default_value = "bandall.toml")]
        config: PathBuf,
    },
    /// Audit log operations.
    Audit {
        /// Audit subcommand.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// HMAC API client operations.
    Apikey {
        /// API key subcommand.
        #[command(subcommand)]
        command: ApikeyCommand,
    },
    /// Tenant operations (operator bootstrapping).
    Tenant {
        /// Tenant subcommand.
        #[command(subcommand)]
        command: TenantCommand,
    },
    /// Prints an example configuration file.
    InitConfig,
    /// Prints the version.
    Version,
    /// Liveness probe for container healthchecks (always exits 0).
    Healthcheck,
}

/// Audit subcommands.
#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Verifies the hash chain, reporting the first bad sequence number.
    Verify {
        /// Configuration file path.
        #[arg(long, env = "BANDALL_CONFIG", default_value = "bandall.toml")]
        config: PathBuf,
        /// Maximum entries to check.
        #[arg(long, default_value = "100000")]
        limit: i64,
    },
}

/// Tenant subcommands.
#[derive(Debug, Subcommand)]
enum TenantCommand {
    /// Creates a tenant, printing its id.
    Create {
        /// Configuration file path.
        #[arg(long, env = "BANDALL_CONFIG", default_value = "bandall.toml")]
        config: PathBuf,
        /// Display name.
        #[arg(long)]
        name: String,
    },
}

/// API key subcommands.
#[derive(Debug, Subcommand)]
enum ApikeyCommand {
    /// Creates an HMAC API client, printing the key once.
    Create {
        /// Configuration file path.
        #[arg(long, env = "BANDALL_CONFIG", default_value = "bandall.toml")]
        config: PathBuf,
        /// Owning tenant id.
        #[arg(long)]
        tenant: String,
        /// Space-separated scopes (e.g. "verify").
        #[arg(long, default_value = "verify")]
        scopes: String,
        /// Key id prefix.
        #[arg(long, default_value = "key")]
        prefix: String,
    },
    /// Revokes an API client.
    Revoke {
        /// Configuration file path.
        #[arg(long, env = "BANDALL_CONFIG", default_value = "bandall.toml")]
        config: PathBuf,
        /// Key id to revoke.
        #[arg(long)]
        key_id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve {
        config: PathBuf::from("bandall.toml"),
    }) {
        Command::Serve { config } => serve(&config),
        Command::Migrate { config } => migrate(&config),
        Command::Audit { command } => match command {
            AuditCommand::Verify { config, limit } => audit_verify(&config, limit),
        },
        Command::Apikey { command } => match command {
            ApikeyCommand::Create {
                config,
                tenant,
                scopes,
                prefix,
            } => apikey_create(&config, &tenant, &scopes, &prefix),
            ApikeyCommand::Revoke { config, key_id } => apikey_revoke(&config, &key_id),
        },
        Command::Tenant { command } => match command {
            TenantCommand::Create { config, name } => tenant_create(&config, &name),
        },
        Command::InitConfig => {
            print!("{}", bandall_api::Config::example());
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("bandall {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Healthcheck => ExitCode::SUCCESS,
    }
}

fn setup_logging() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "bandall=info".to_string());
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn serve(config_path: &std::path::Path) -> ExitCode {
    setup_logging();
    let config = load_config(config_path);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match bandall_api::server::build_state(&config).await {
            Ok((state, kind)) => {
                tracing::info!(store = ?kind, "state ready");
                match bandall_api::server::serve(&config, state).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("server error: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
            Err(e) => {
                eprintln!("startup error: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn migrate(config_path: &std::path::Path) -> ExitCode {
    setup_logging();
    let config = load_config(config_path);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match bandall_api::server::build_state(&config).await {
            Ok(_) => {
                println!("migrations applied");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("migration error: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Verifies the audit hash chain, exiting non-zero on the first bad entry.
fn audit_verify(config_path: &std::path::Path, limit: i64) -> ExitCode {
    setup_logging();
    let config = load_config(config_path);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match bandall_api::server::build_state(&config).await {
            Ok((state, _)) => match state.store.list_audit(limit).await {
                Ok(entries) => match bandall_api::audit::verify_chain(&entries) {
                    Ok(()) => {
                        println!("audit chain OK ({} entries)", entries.len());
                        ExitCode::SUCCESS
                    }
                    Err(seq) => {
                        eprintln!("audit chain BROKEN at seq {seq}");
                        ExitCode::FAILURE
                    }
                },
                Err(e) => {
                    eprintln!("cannot read audit log: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("startup error: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn load_config(path: &std::path::Path) -> bandall_api::Config {
    match bandall_api::Config::load(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    }
}

/// Creates a tenant, printing its id (operator bootstrapping, e.g. load
/// fixtures and the H6 demo).
fn tenant_create(config_path: &std::path::Path, name: &str) -> ExitCode {
    setup_logging();
    let config = load_config(config_path);
    let now_i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match bandall_api::server::build_state(&config).await {
            Ok((state, _)) => match state.store.create_tenant(name, now_i64).await {
                Ok(tenant) => {
                    println!("tenant_id: {}", tenant.id);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cannot create tenant: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("startup error: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Lowercase hex encoding for one-time key display.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Creates an HMAC API client, sealing its key and printing it once.
fn apikey_create(
    config_path: &std::path::Path,
    tenant: &str,
    scopes: &str,
    prefix: &str,
) -> ExitCode {
    setup_logging();
    let config = load_config(config_path);
    let mut raw = vec![0u8; 32];
    if getrandom::getrandom(&mut raw).is_err() {
        eprintln!("cannot gather randomness");
        return ExitCode::FAILURE;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let key_suffix: String = hex_encode(&raw).chars().take(12).collect();
    let key_id = format!("{prefix}-{key_suffix}");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match bandall_api::server::build_state(&config).await {
            Ok((state, _)) => {
                let sealed = match state.vault.seal("api-clients", tenant, &key_id, &raw) {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        eprintln!("cannot seal key: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                let now_i64 = i64::try_from(now).unwrap_or(0);
                let created = state
                    .store
                    .create_api_client(bandall_api::NewApiClient {
                        key_id: key_id.clone(),
                        tenant_id: tenant.to_string(),
                        sealed_version: 1,
                        kek_id: state.vault.kek_id().to_string(),
                        wrapped_dek: sealed.wrapped_dek().ciphertext().to_vec(),
                        wrapped_nonce: sealed.wrapped_dek().nonce().to_vec(),
                        nonce: sealed.nonce().to_vec(),
                        ciphertext: sealed.ciphertext().to_vec(),
                        scopes: scopes.to_string(),
                        created_at: now_i64,
                    })
                    .await;
                match created {
                    Ok(_) => {
                        println!("key_id: {key_id}");
                        println!("key: {}", hex_encode(&raw));
                        println!("scopes: {scopes}");
                        println!("store the key now; it is never shown again");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("cannot store client: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
            Err(e) => {
                eprintln!("startup error: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Revokes an HMAC API client.
fn apikey_revoke(config_path: &std::path::Path, key_id: &str) -> ExitCode {
    setup_logging();
    let config = load_config(config_path);
    let now_i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match bandall_api::server::build_state(&config).await {
            Ok((state, _)) => match state.store.revoke_api_client(key_id, now_i64).await {
                Ok(()) => {
                    println!("revoked {key_id}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cannot revoke client: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("startup error: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use super::Command;
    use clap::Parser;

    #[test]
    fn parses_serve_with_config() {
        let cli = Cli::parse_from(["bandall", "serve", "--config", "/tmp/x.toml"]);
        assert!(matches!(cli.command, Some(Command::Serve { .. })));
    }
}
