//! H6, ítem 6: modo embebido a través de la fachada `bandall-embedded`
//! (ADR-0014) — un binario único, sin red y sin HTTP.
//!
//! La fachada es el camino recomendado para integrar BandAll como librería:
//! expone enroll → confirm → verify con las mismas garantías que el servicio
//! (secreto cifrado con la KEK que el integrador aporta, antirreplay atómico,
//! deriva acotada, recovery codes), y esconde todo el cableado.
//!
//! ```sh
//! cargo run -p bandall-embedded --example embedded
//! ```
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use bandall_embedded::{Embedded, Error};

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Error> {
    // 1. Estado local: SQLite en un archivo temporal + KEK inyectada (en una
    //    app real viene del Keystore/Keychain del dispositivo).
    let path = std::env::temp_dir().join("bandall-embedded-demo.db");
    let _ = std::fs::remove_file(&path);
    let embedded = Embedded::sqlite_path(path.to_str().ok_or(Error::Internal)?, [7u8; 32]).await?;

    // 2. Enrolar: el tenant, el sujeto y el factor se crean aquí mismo.
    let tenant = embedded.create_tenant("acme").await?;
    let enrolled = embedded
        .enroll(&tenant, "alice", "BandAll", "alice@example.com")
        .await?;
    println!(
        "enrolado: factor {} — código QR listo (secreto cifrado en SQLite)",
        enrolled.factor_id
    );

    // 3. El usuario introduce el primer código de su autenticador: confirma.
    //    En la vida real el código llega de la app; aquí se genera con la
    //    misma URI que estamos a punto de imprimir, para que el ejemplo sea
    //    autónomo.
    let secret_b32 = enrolled
        .otpauth_uri
        .split("secret=")
        .nth(1)
        .ok_or(Error::Internal)?
        .split('&')
        .next()
        .ok_or(Error::Internal)?;
    let params = bandall_totp_core::TotpParams::default_params();
    let secret = bandall_totp_core::Secret::from_base32(secret_b32)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let code = bandall_totp_core::totp::generate(&secret, params, now)?;

    let recovery = embedded
        .confirm(&tenant, "alice", &enrolled.factor_id, &code, now)
        .await?;
    println!(
        "confirmado: {} códigos de recuperación emitidos",
        recovery.len()
    );

    // 4. Verificar un código nuevo (el paso ya consumido lo rechazaría).
    let next = bandall_totp_core::totp::generate(&secret, params, now + 120)?;
    embedded
        .verify(&tenant, "alice", &enrolled.factor_id, &next, now + 120)
        .await?;
    println!("código verificado offline (ventana + deriva, antirreplay atómico)");

    let replay = bandall_totp_core::totp::generate(&secret, params, now + 121)?;
    match embedded
        .verify(&tenant, "alice", &enrolled.factor_id, &replay, now + 121)
        .await
    {
        Ok(()) => return Err(Error::Internal), // un replay aceptado es un bug
        Err(Error::Unverified) => println!("replay rechazado: el código no vale dos veces"),
        Err(other) => return Err(other),
    }

    println!("modo embebido OK: sin red, sin HTTP, secreto cifrado en reposo");
    Ok(())
}
