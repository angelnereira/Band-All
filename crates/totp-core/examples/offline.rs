//! Offline TOTP for air-gapped clients: no network, no database.
//!
//! ```sh
//! cargo run -p bandall-totp-core --example offline
//! ```
//!
//! Mirrors what `authenticator-core` (H7) does on device: provision from an
//! `otpauth://` URI, show the current code with its remaining seconds, and
//! verify with an explicitly passed clock.
//!
//! This example is a CLI, so printing is expected here (like the `bandall`
//! binary) even though libraries must stay silent.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use bandall_totp_core::{Otpauth, Secret, TotpParams, totp};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    // In production this URI arrives once, as a QR code.
    let uri = "otpauth://totp/BandAll:demo@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=BandAll&algorithm=SHA256&digits=6&period=30";
    let entry = Otpauth::parse(uri).map_err(|error| error.to_string())?;
    let params = TotpParams::new(
        entry.params().algorithm(),
        entry.params().digits(),
        entry.params().period(),
    )
    .map_err(|error| error.to_string())?;

    // Device clock, read once and passed explicitly (never inside the core).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|window| window.as_secs())
        .map_err(|error| format!("clock: {error}"))?;

    let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .map_err(|error| error.to_string())?;
    let code = totp::generate(&secret, params, now).map_err(|error| error.to_string())?;
    let period = params.period().as_u64();
    let remaining = period.saturating_sub(now % period);
    println!("account:  {}", entry.account());
    println!("code:     {code} (expires in {remaining}s)");

    match totp::verify(&secret, params, &code, now, 1, None) {
        Ok(step) => println!("verified at step {}", step.get()),
        Err(error) => println!("rejected: {error}"),
    }
    Ok(())
}
