//! Verification gates: atomic rate limiting and timing-uniform denial.
//!
//! Every user-facing verification path *acquires* its factor, tenant and (when
//! known) client-IP keys before verifying and *records* the outcome after.
//! `acquire` decides and records the attempt in one critical section (lock or
//! database transaction), so a concurrent burst stops exactly at the limit
//! (remediation T2).
//!
//! `X-Forwarded-For` is only honoured from configured trusted proxies; the
//! chain is walked right-to-left skipping trusted hops so a client cannot
//! spoof its address. Unknown factors cost a dummy verification so misses and
//! mismatches take similar time.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{HeaderMap, request::Parts};
use bandall_policy::{Decision, Scope};
use bandall_totp_core::{Secret, TotpParams};

use crate::config::TrustedProxies;
use crate::error::Error;
use crate::state::{AppState, PolicyHandle};

/// Maximum `X-Forwarded-For` hops inspected (bounded work on hostile input).
const MAX_FORWARDED_HOPS: usize = 32;

/// A composed policy key with its scope.
#[derive(Debug, Clone)]
pub struct GateKey {
    /// Scope selecting limits (and backend rows).
    pub scope: Scope,
    /// Key within the scope (`factor:…`, `tenant:…`, `ip:…`).
    pub key: String,
}

/// Builds the per-factor policy key.
#[must_use]
pub fn factor_key(tenant_id: &str, subject_id: &str, factor_id: &str) -> GateKey {
    GateKey {
        scope: Scope::Factor,
        key: format!("factor:{tenant_id}:{subject_id}:{factor_id}"),
    }
}

/// Builds the per-tenant policy key.
#[must_use]
pub fn tenant_key(tenant_id: &str) -> GateKey {
    GateKey {
        scope: Scope::Tenant,
        key: format!("tenant:{tenant_id}"),
    }
}

/// Builds the per-address policy key.
#[must_use]
pub fn ip_key(addr: IpAddr) -> GateKey {
    GateKey {
        scope: Scope::Ip,
        key: format!("ip:{addr}"),
    }
}

/// Peer socket address, when the server runs with connect info (always in
/// service mode; `None` in unit tests that call handlers directly).
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerAddr(pub Option<SocketAddr>);

impl<S> FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let addr = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        Ok(Self(addr))
    }
}

/// Resolves the client address for IP-scoped limits.
///
/// Returns the socket peer unless it is a trusted proxy, in which case the
/// rightmost untrusted `X-Forwarded-For` hop wins. A malformed chain falls
/// back to the peer (never to an attacker-supplied value).
#[must_use]
pub fn client_ip(
    trusted_proxies: &TrustedProxies,
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
) -> Option<IpAddr> {
    let peer = peer?.ip();
    if !trusted_proxies.contains(peer) {
        return Some(peer);
    }
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    if let Some(forwarded) = forwarded {
        for candidate in forwarded.split(',').rev().take(MAX_FORWARDED_HOPS) {
            let candidate = candidate.trim();
            if candidate.is_empty() {
                continue;
            }
            match candidate.parse::<IpAddr>() {
                Ok(addr) if !trusted_proxies.contains(addr) => return Some(addr),
                Ok(_) => {}
                Err(_) => return Some(peer),
            }
        }
    }
    Some(peer)
}

/// Acquires every key; denies when any scope is over its limit.
pub async fn acquire(state: &AppState, keys: &[GateKey], now_secs: u64) -> Result<(), Error> {
    for key in keys {
        let decision = match &state.policy {
            PolicyHandle::Memory(policy) => policy.acquire(key.scope, &key.key, now_secs),
            PolicyHandle::Database(config) => {
                let limits = config.limits(key.scope);
                let now = i64::try_from(now_secs).map_err(|_| Error::Unavailable)?;
                state
                    .store
                    .reserve_auth_attempt(&key.key, now, limits)
                    .await
                    .map_err(|_| Error::Unavailable)?
            }
        };
        if decision != Decision::Allow {
            return Err(Error::RateLimited);
        }
    }
    Ok(())
}

/// Releases the acquired keys. Success clears them; failures stay recorded
/// (they were reserved by [`acquire`], refused attempts never are).
pub async fn record(state: &AppState, keys: &[GateKey], success: bool) -> Result<(), Error> {
    if !success {
        return Ok(());
    }
    for key in keys {
        match &state.policy {
            PolicyHandle::Memory(policy) => policy.record(&key.key, true),
            PolicyHandle::Database(_) => {
                state
                    .store
                    .clear_auth_failures(&key.key)
                    .await
                    .map_err(|_| Error::Unavailable)?;
            }
        }
    }
    Ok(())
}

/// Timing ballast for unknown factors: runs the same HMAC math as a real
/// check so misses cost roughly like mismatches.
pub fn dummy_verify() {
    let params = TotpParams::default_params();
    if let Ok(secret) = Secret::new(vec![7u8; 32]) {
        match bandall_totp_core::totp::verify(&secret, params, "000000", 0, 1, None) {
            Ok(_) | Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client_ip;
    use crate::config::TrustedProxies;
    use axum::http::HeaderMap;

    fn forwarded(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());
        headers
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_for() {
        let trusted = TrustedProxies::parse(&["10.0.0.5".to_string()]).unwrap();
        let headers = forwarded("203.0.113.9");
        let peer = Some("198.51.100.7:1234".parse().unwrap());
        assert_eq!(
            client_ip(&trusted, peer, &headers),
            Some("198.51.100.7".parse().unwrap())
        );
    }

    #[test]
    fn rightmost_untrusted_hop_wins_behind_proxy() {
        let trusted = TrustedProxies::parse(&["10.0.0.0/8".to_string()]).unwrap();
        let headers = forwarded("203.0.113.9, 10.0.0.8");
        let peer = Some("10.0.0.5:443".parse().unwrap());
        assert_eq!(
            client_ip(&trusted, peer, &headers),
            Some("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn malformed_chain_falls_back_to_peer() {
        let trusted = TrustedProxies::parse(&["10.0.0.5".to_string()]).unwrap();
        let headers = forwarded("not-an-ip");
        let peer = Some("10.0.0.5:443".parse().unwrap());
        assert_eq!(client_ip(&trusted, peer, &headers), peer.map(|p| p.ip()));
    }

    #[test]
    fn without_proxy_config_the_socket_wins() {
        let trusted = TrustedProxies::default();
        let headers = forwarded("203.0.113.9");
        let peer = Some("10.0.0.5:443".parse().unwrap());
        assert_eq!(client_ip(&trusted, peer, &headers), peer.map(|p| p.ip()));
        assert_eq!(client_ip(&trusted, None, &headers), None);
    }
}
