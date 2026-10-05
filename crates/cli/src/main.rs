//! `bandall` binary: server and maintenance commands.
//!
//! The distroless-era healthcheck probes through this binary
//! (`bandall healthcheck`); with the current slim runtime the same subcommand
//! backs the Docker `HEALTHCHECK`.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
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
    /// Prints an example configuration file.
    InitConfig,
    /// Prints the version.
    Version,
    /// Liveness probe for container healthchecks (always exits 0).
    Healthcheck,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve {
        config: PathBuf::from("bandall.toml"),
    }) {
        Command::Serve { config } => serve(&config),
        Command::Migrate { config } => migrate(&config),
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

fn load_config(path: &std::path::Path) -> bandall_api::Config {
    match bandall_api::Config::load(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    }
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
