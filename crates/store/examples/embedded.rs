//! H6, ítem 6: modo embebido — BandAll como biblioteca, sin red y sin HTTP.
//!
//! Un binario único que enrula y verifica códigos TOTP usando solo
//! `bandall-totp-core` (la matemática) + `bandall-store` (SQLite local para la
//! persistencia y el antirreplay) + `bandall-vault` (el secreto se guarda
//! cifrado, igual que el servicio). No hay servidor, no hay socket: todo corre
//! en el proceso.
//!
//! Hasta el 2026-10-06 no existía un ejemplo que juntara `store` con la
//! verificación: `crates/totp-core/examples/offline.rs` demostraba la
//! matemática sin persistencia, y el camino completo solo se ejercitaba vía
//! HTTP. Este ejemplo es el "modo embebido" que el roadmap H6 pide: verifica
//! códigos sin conexión, con el mismo antirreplay atómico y el mismo cifrado.
//!
//! ```sh
//! cargo run -p bandall-store --example embedded
//! ```
//!
//! Es un ejemplo, así que imprime (como el binario `bandall`), pero el store
//! y el vault son los de producción.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;
use std::sync::Arc;

use bandall_store::{NewFactor, SqliteStore, Store, new_factor_id};
use bandall_totp_core::{Algorithm, Secret, TotpParams, totp};
use bandall_vault::{LocalKms, Vault};
use secrecy::ExposeSecret;

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

async fn run() -> Result<(), String> {
    // --- 1. Estado local: SQLite en memoria + vault con KEK en memoria.
    // En una app embebida de verdad la KEK vendría del Keystore/Keychain del
    // dispositivo; aquí la inyectamos para que el ejemplo sea autónomo.
    let store = Arc::new(SqliteStore::in_memory().await.map_err(|e| e.to_string())?);
    store.migrate().await.map_err(|e| e.to_string())?;
    let kms = Arc::new(
        LocalKms::from_bytes("kek-embedded".to_string(), [7u8; 32].to_vec())
            .map_err(|e| e.to_string())?,
    );
    let vault = Arc::new(Vault::new(kms));

    // --- 2. Enrolar: tenant, sujeto y factor con el secreto cifrado.
    let now = 1_700_000_000i64;
    let tenant = store
        .create_tenant("acme", now)
        .await
        .map_err(|e| e.to_string())?;
    let subject = store
        .create_subject(&tenant.id, "alice", now)
        .await
        .map_err(|e| e.to_string())?;

    let secret = Secret::generate_for(Algorithm::Sha256).map_err(|e| e.to_string())?;
    let factor_id = new_factor_id();
    let sealed = vault
        .seal(
            &tenant.id,
            &subject.id,
            &factor_id,
            secret.expose_secret_bytes(),
        )
        .map_err(|e| e.to_string())?;
    store
        .create_factor(NewFactor {
            id: factor_id.clone(),
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            status: "active".to_string(),
            secret_version: 1,
            kek_id: vault.kek_id().to_string(),
            wrapped_dek: sealed.wrapped_dek().ciphertext().to_vec(),
            wrapped_nonce: sealed.wrapped_dek().nonce().to_vec(),
            nonce: sealed.nonce().to_vec(),
            ciphertext: sealed.ciphertext().to_vec(),
            algorithm: "SHA256".to_string(),
            digits: 6,
            period: 30,
            created_at: now,
        })
        .await
        .map_err(|e| e.to_string())?;
    println!("factor enrulado: {factor_id} (secreto cifrado en SQLite)");

    // --- 3. Verificación offline, igual que el servidor: abrir el secreto,
    // generar el código del reloj inyectado, verificar con ventana ±1 y
    // persistir el paso con antirreplay atómico.
    let params = TotpParams::default_params();
    let unix_secs = 1_700_000_030u64;

    let stored = store
        .get_factor(&tenant.id, &subject.id, &factor_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "factor desapareció".to_string())?;
    let sealed_back = bandall_vault::SealedSecret::reassemble(
        1,
        stored.kek_id.clone(),
        bandall_vault::WrappedDek::new(
            stored
                .wrapped_nonce
                .as_slice()
                .try_into()
                .map_err(|_| "wrap nonce inválido".to_string())?,
            stored.wrapped_dek.clone(),
        ),
        stored
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| "nonce inválido".to_string())?,
        stored.ciphertext.clone(),
    );
    let opened = vault
        .open(
            &sealed_back,
            &stored.tenant_id,
            &stored.subject_id,
            &stored.id,
        )
        .map_err(|e| e.to_string())?;
    let secret = Secret::new(opened.expose_secret().to_vec()).map_err(|e| e.to_string())?;

    let code = totp::generate(&secret, params, unix_secs).map_err(|e| e.to_string())?;
    let step =
        totp::verify(&secret, params, &code, unix_secs, 1, None).map_err(|e| e.to_string())?;
    let accepted = store
        .cas_last_step(&factor_id, step.get())
        .await
        .map_err(|e| e.to_string())?;
    if !accepted {
        return Err("el código correcto fue rechazado por antirreplay".to_string());
    }
    println!("código {code} verificado offline en el paso {}", step.get());

    // --- 4. Replay: el mismo código, un instante después, debe ser rechazado.
    let replay = totp::verify(&secret, params, &code, unix_secs + 1, 1, None);
    let replayed = match replay {
        Ok(step) => store
            .cas_last_step(&factor_id, step.get())
            .await
            .map_err(|e| e.to_string())?,
        Err(_) => false,
    };
    if replayed {
        return Err("un código reutilizado fue aceptado".to_string());
    }
    println!("replay del mismo código: rechazado (antirreplay atómico)");
    println!("modo embebido OK: sin red, sin HTTP, secreto cifrado en reposo");
    Ok(())
}
