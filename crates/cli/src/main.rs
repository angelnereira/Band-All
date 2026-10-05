//! bandall binary: CLI entrypoint (init, migrate, rotate-keys, audit...).
//!
//! H0 only ships a skeleton so the container image has an executable and a
//! healthcheck probe. Real commands arrive with their milestones.
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

use std::process::ExitCode;

fn main() -> ExitCode {
    let command = std::env::args().nth(1);
    if matches!(command.as_deref(), None | Some("version")) {
        println!("bandall {}", env!("CARGO_PKG_VERSION"));
    }
    ExitCode::from(exit_code_for(command.as_deref()))
}

/// Maps a command name to the process exit code.
///
/// `version` and `healthcheck` exist from H0 so Docker can probe the binary;
/// unknown commands fail closed with exit code 2.
fn exit_code_for(command: Option<&str>) -> u8 {
    match command {
        None | Some("version") | Some("healthcheck") => 0,
        Some(_) => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::exit_code_for;

    #[test]
    fn healthcheck_exits_successfully() {
        assert_eq!(exit_code_for(Some("healthcheck")), 0);
    }

    #[test]
    fn version_exits_successfully() {
        assert_eq!(exit_code_for(Some("version")), 0);
        assert_eq!(exit_code_for(None), 0);
    }

    #[test]
    fn unknown_command_fails_closed() {
        assert_eq!(exit_code_for(Some("bogus")), 2);
    }
}
