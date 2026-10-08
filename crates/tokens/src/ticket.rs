//! WebSocket connection tickets (ADR-0017).
//!
//! A browser cannot put a header on a WebSocket `Upgrade`, and an access token
//! in the query string would leak into proxy logs, `Referer` and history. The
//! ticket is the middle path: the client exchanges a valid access token for a
//! short-lived, single-use value that the *service* redeems when the connection
//! opens.
//!
//! Same discipline as refresh tokens: 256 bits from the OS CSPRNG, stored only
//! as a SHA-256 hash, plaintext shown exactly once. The short lifetime (30 s)
//! means a leaked ticket is dead before it can be used twice, and single-use is
//! enforced by the store's atomic claim, so the same ticket cannot open two
//! connections.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::Error;
use crate::refresh::hash_plaintext;

/// Ticket entropy in bytes.
const TICKET_BYTES: usize = 32;
/// Ticket lifetime in seconds: long enough to reach the service after the
/// HTTP exchange, short enough that a leak is useless.
pub const WS_TICKET_TTL_SECS: u64 = 30;

/// A fresh connection ticket: plaintext for the client, hash for storage.
#[derive(Debug)]
pub struct WsTicket {
    /// Plaintext ticket (shown once).
    pub plaintext: String,
    /// SHA-256 hash in hex (persisted).
    pub hash: String,
}

impl WsTicket {
    /// Generates a fresh ticket from the OS CSPRNG.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = vec![0u8; TICKET_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
        let plaintext = URL_SAFE_NO_PAD.encode(&bytes);
        let hash = hash_plaintext(&plaintext);
        Ok(Self { plaintext, hash })
    }
}

#[cfg(test)]
mod tests {
    use super::{WS_TICKET_TTL_SECS, WsTicket, hash_plaintext};

    #[test]
    fn ticket_is_opaque_and_hashed() {
        let ticket = WsTicket::generate().unwrap();
        assert_eq!(ticket.hash.len(), 64, "SHA-256 hex");
        assert!(!ticket.hash.contains(&ticket.plaintext));
        assert_eq!(ticket.plaintext.len(), 43, "32 bytes, base64url unpadded");
    }

    #[test]
    fn tickets_are_unique() {
        let first = WsTicket::generate().unwrap();
        let second = WsTicket::generate().unwrap();
        assert_ne!(first.plaintext, second.plaintext);
        assert_ne!(first.hash, second.hash);
    }

    #[test]
    fn ttl_is_short_by_design() {
        // The whole point is that the value is useless once spent or stale.
        const { assert!(WS_TICKET_TTL_SECS <= 30, "a longer ticket is a bigger leak") };
    }

    #[test]
    fn hashing_matches_the_refresh_pattern() {
        let ticket = WsTicket::generate().unwrap();
        assert_eq!(hash_plaintext(&ticket.plaintext), ticket.hash);
    }
}
