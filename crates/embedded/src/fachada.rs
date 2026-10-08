//! The embedded facade (ADR-0014): a high-level, safe surface over
//! `totp-core` + `vault` + `store` for systems that embed BandAll in-process.
//!
//! Everything here is what the HTTP service does, but called directly: same
//! sealed secrets, same AAD, same atomic anti-replay, same bounded drift. The
//! facade keeps the clock seam explicit (`unix_secs` is a parameter, never
//! `SystemTime` inside the core), so the integrating application controls its
//! time (tests, devices with unreliable clocks).

use std::sync::Arc;

use bandall_store::{Factor, NewFactor, Store, new_factor_id};
use bandall_totp_core::{Algorithm, Otpauth, Period, Secret, TotpParams, totp};
use bandall_vault::{LocalKms, Vault};
use secrecy::ExposeSecret as _;

use crate::error::Error;

/// Rebuilds the sealed secret from a factor row (inverse of `enroll`).
fn sealed_from_row(factor: &Factor) -> Result<bandall_vault::SealedSecret, Error> {
    use bandall_vault::{SealedSecret, WrappedDek};
    let version = u8::try_from(factor.secret_version).map_err(|_| Error::Internal)?;
    let wrap_nonce: [u8; 24] = factor
        .wrapped_nonce
        .clone()
        .try_into()
        .map_err(|_| Error::Internal)?;
    let nonce: [u8; 24] = factor
        .nonce
        .clone()
        .try_into()
        .map_err(|_| Error::Internal)?;
    Ok(SealedSecret::reassemble(
        version,
        factor.kek_id.clone(),
        WrappedDek::new(wrap_nonce, factor.wrapped_dek.clone()),
        nonce,
        factor.ciphertext.clone(),
    ))
}

/// TOTP parameters from a factor row.
fn params_from_row(factor: &Factor) -> Result<TotpParams, Error> {
    let algorithm = Algorithm::from_name(&factor.algorithm)?;
    let digits = u8::try_from(factor.digits).map_err(|_| Error::Internal)?;
    let period_secs = u64::try_from(factor.period).map_err(|_| Error::Internal)?;
    TotpParams::new(algorithm, digits, Period::new(period_secs)?).map_err(|_| Error::Internal)
}

/// Result of [`Embedded::enroll`]: what the QR code and the recovery flow
/// need. The secret only ever leaves the facade inside the `otpauth` URI.
#[derive(Debug, Clone)]
pub struct EnrollOutcome {
    /// Factor id.
    pub factor_id: String,
    /// `otpauth://` URI for the QR code (secret inside, shown once).
    pub otpauth_uri: String,
    /// Recovery codes (shown once; only hashes are stored).
    pub recovery_codes: Vec<String>,
}

/// Embedded BandAll instance: a store (SQLite path or injected) plus a vault
/// wrapping a KEK owned by the integrating application.
pub struct Embedded {
    store: Arc<dyn Store>,
    vault: Arc<Vault>,
}

impl std::fmt::Debug for Embedded {
    /// Opaque: holds key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Embedded").finish_non_exhaustive()
    }
}

impl Embedded {
    /// Opens (or creates) a SQLite database at `path` and a vault with `kek`.
    /// The KEK is 32 raw bytes injected by the caller (OS keychain, sealed
    /// file, platform secure store); the facade never derives it.
    pub async fn sqlite_path(path: &str, kek: [u8; 32]) -> Result<Self, Error> {
        let store = bandall_store::SqliteStore::connect(path).await?;
        store.migrate().await?;
        Self::with_store(Arc::new(store), kek)
    }

    /// In-memory store (tests, ephemeral integrations).
    pub async fn in_memory(kek: [u8; 32]) -> Result<Self, Error> {
        let store = bandall_store::SqliteStore::in_memory().await?;
        store.migrate().await?;
        Self::with_store(Arc::new(store), kek)
    }

    /// Store + vault from parts the integrator already owns. This is the
    /// escape hatch for a Postgres store or a KMS-backed vault
    /// ([`bandall_vault::KmsProvider`]).
    pub fn with_store(store: Arc<dyn Store>, kek: [u8; 32]) -> Result<Self, Error> {
        let kms = LocalKms::from_bytes("embedded-kek".to_string(), kek.to_vec())
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            store,
            vault: Arc::new(Vault::new(Arc::new(kms))),
        })
    }

    /// Store + fully custom vault (KMS).
    pub fn with_parts(store: Arc<dyn Store>, vault: Arc<Vault>) -> Self {
        Self { store, vault }
    }

    /// Tenant handle: `create_tenant` exists in the store; the facade adds a
    /// wrapper so an integrator can bootstrap without knowing store details.
    pub async fn create_tenant(&self, name: &str) -> Result<String, Error> {
        let now = now_unix();
        Ok(self.store.create_tenant(name, now).await?.id)
    }

    /// Ensures the subject exists (creates it on first use, like the service)
    /// and provisions a `pending` factor with a fresh secret. Confirmation is
    /// [`Embedded::confirm`].
    pub async fn enroll(
        &self,
        tenant: &str,
        subject_external_id: &str,
        issuer: &str,
        account: &str,
    ) -> Result<EnrollOutcome, Error> {
        if subject_external_id.is_empty() {
            return Err(Error::MissingSubject);
        }
        if account.is_empty() {
            return Err(Error::MissingAccount);
        }
        let now = now_unix();

        let subject = match self.store.find_subject(tenant, subject_external_id).await? {
            Some(subject) => subject,
            None => {
                self.store
                    .create_subject(tenant, subject_external_id, now)
                    .await?
            }
        };

        let secret = Secret::generate_for(Algorithm::Sha256)?;
        let factor_id = new_factor_id();
        let sealed = self.vault.seal(
            tenant,
            &subject.id,
            &factor_id,
            secret.expose_secret_bytes(),
        )?;

        let params = TotpParams::default_params();
        let entry = Otpauth::new(params, secret, issuer.to_string(), account.to_string())?;
        self.store
            .create_factor(NewFactor {
                id: factor_id.clone(),
                tenant_id: tenant.to_string(),
                subject_id: subject.id.clone(),
                status: "pending".to_string(),
                secret_version: 1,
                kek_id: self.vault.kek_id().to_string(),
                wrapped_dek: sealed.wrapped_dek().ciphertext().to_vec(),
                wrapped_nonce: sealed.wrapped_dek().nonce().to_vec(),
                nonce: sealed.nonce().to_vec(),
                ciphertext: sealed.ciphertext().to_vec(),
                algorithm: "SHA256".to_string(),
                digits: 6,
                period: 30,
                created_at: now,
            })
            .await?;

        Ok(EnrollOutcome {
            factor_id,
            otpauth_uri: entry.to_uri(),
            recovery_codes: Vec::new(),
        })
    }

    /// Confirmation step, mirroring the service: the first code proves the
    /// device owns the secret, the factor becomes active and recovery codes
    /// are issued (hashed in store, plaintext returned once).
    ///
    /// `subject` is the caller-facing external id used at enrolment time; the
    /// facade resolves it to the internal one internally.
    pub async fn confirm(
        &self,
        tenant: &str,
        subject_external: &str,
        factor_id: &str,
        code: &str,
        unix_secs: u64,
    ) -> Result<Vec<String>, Error> {
        let subject = self.internal_subject(tenant, subject_external).await?;
        let factor = self
            .store
            .get_factor(tenant, &subject, factor_id)
            .await?
            .ok_or(Error::Unverified)?;
        if factor.status != "pending" {
            return Err(Error::FactorState);
        }
        let opened = self
            .vault
            .open(&sealed_from_row(&factor)?, tenant, &subject, factor_id)?;
        let secret = Secret::new(opened.expose_secret().to_vec())?;
        let params = params_from_row(&factor)?;
        let step = totp::verify(&secret, params, code, unix_secs, 1, None)?;
        if !self.store.cas_last_step(factor_id, step.get()).await? {
            return Err(Error::Unverified);
        }
        self.store
            .confirm_factor(factor_id, i64::try_from(unix_secs).unwrap_or(0))
            .await?;

        let codes = bandall_vault::recovery::generate()?;
        let mut hashes = Vec::with_capacity(codes.len());
        let mut displays = Vec::with_capacity(codes.len());
        for code in &codes {
            hashes.push(bandall_vault::recovery::hash(code)?);
            displays.push(code.display());
        }
        self.store.add_recovery_codes(factor_id, &hashes).await?;
        Ok(displays)
    }

    /// Verifies a code offline: window around the injected clock, atomic
    /// anti-replay and drift persistence — exactly what the HTTP service does.
    pub async fn verify(
        &self,
        tenant: &str,
        subject_external: &str,
        factor_id: &str,
        code: &str,
        unix_secs: u64,
    ) -> Result<(), Error> {
        let subject = self.internal_subject(tenant, subject_external).await?;
        let factor = self
            .store
            .get_factor(tenant, &subject, factor_id)
            .await?
            .ok_or(Error::Unverified)?;
        if factor.status != "active" {
            return Err(Error::FactorState);
        }
        let opened = self
            .vault
            .open(&sealed_from_row(&factor)?, tenant, &subject, factor_id)?;
        let secret = Secret::new(opened.expose_secret().to_vec())?;
        let params = params_from_row(&factor)?;
        let step = totp::verify(&secret, params, code, unix_secs, 1, None)?;
        if !self.store.cas_last_step(factor_id, step.get()).await? {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    /// Removes a factor (post-recovery re-enrolment), like the service does.
    pub async fn delete_factor(
        &self,
        tenant: &str,
        subject_external: &str,
        factor_id: &str,
    ) -> Result<(), Error> {
        let subject = self.internal_subject(tenant, subject_external).await?;
        // Scoped check so a wrong tenant/subject cannot delete another row.
        if self
            .store
            .get_factor(tenant, &subject, factor_id)
            .await?
            .is_none()
        {
            return Err(Error::Unverified);
        }
        self.store.delete_factor(factor_id).await?;
        Ok(())
    }

    /// Resolves the caller-facing external id to the internal subject row.
    async fn internal_subject(&self, tenant: &str, external: &str) -> Result<String, Error> {
        self.store
            .find_subject(tenant, external)
            .await?
            .map(|subject| subject.id)
            .ok_or(Error::Unverified)
    }
}

/// Current Unix seconds, read once. The facade is the only place that touches
/// the clock; the core stays pure.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0)
}
