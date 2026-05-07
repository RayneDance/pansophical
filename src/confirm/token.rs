//! One-time confirmation tokens.
//!
//! Each token is a UUID + HMAC-SHA256(server_secret, uuid + expiry_epoch).
//! Tokens are single-use and expire after `confirm_timeout_secs`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// A signed, one-time confirmation token.
#[derive(Debug, Clone)]
pub struct ConfirmToken {
    /// The UUID portion of the token.
    pub id: String,
    /// Expiry as Unix epoch seconds.
    pub expires_at: u64,
    /// HMAC signature.
    pub signature: String,
}

impl ConfirmToken {
    /// Generate a new token signed with the server secret.
    pub fn generate(server_secret: &str, ttl_secs: u64) -> Self {
        let id = Uuid::new_v4().to_string();
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + ttl_secs;

        let signature = Self::sign(server_secret, &id, expires_at);

        Self {
            id,
            expires_at,
            signature,
        }
    }

    /// Compute the HMAC signature for a token.
    fn sign(server_secret: &str, id: &str, expires_at: u64) -> String {
        let mut mac =
            HmacSha256::new_from_slice(server_secret.as_bytes()).expect("HMAC key length");
        mac.update(id.as_bytes());
        mac.update(b"|");
        mac.update(expires_at.to_string().as_bytes());
        let result = mac.finalize();
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            result.into_bytes(),
        )
    }

    /// The combined token string: `{id}.{expires_at}.{signature}`.
    pub fn to_string_token(&self) -> String {
        format!("{}.{}.{}", self.id, self.expires_at, self.signature)
    }

    /// Parse and verify a token string.
    pub fn verify(server_secret: &str, token_str: &str) -> Result<Self, String> {
        let parts: Vec<&str> = token_str.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err("invalid token format".into());
        }

        let id = parts[0].to_string();
        let expires_at: u64 = parts[1]
            .parse()
            .map_err(|_| "invalid expiry".to_string())?;
        let signature = parts[2].to_string();

        // Verify HMAC.
        let expected = Self::sign(server_secret, &id, expires_at);
        if signature != expected {
            return Err("invalid signature".into());
        }

        // Check expiry.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > expires_at {
            return Err("token expired".into());
        }

        Ok(Self {
            id,
            expires_at,
            signature,
        })
    }

    /// Time remaining before expiry.
    #[allow(dead_code)]
    pub fn ttl(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            Duration::from_secs(self.expires_at - now)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify() {
        let token = ConfirmToken::generate("test_secret", 60);
        let token_str = token.to_string_token();
        let verified = ConfirmToken::verify("test_secret", &token_str).unwrap();
        assert_eq!(verified.id, token.id);
        assert_eq!(verified.expires_at, token.expires_at);
    }

    #[test]
    fn invalid_signature() {
        let token = ConfirmToken::generate("test_secret", 60);
        let token_str = token.to_string_token();
        let result = ConfirmToken::verify("wrong_secret", &token_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid signature"));
    }

    #[test]
    fn expired_token() {
        // Generate a token with 1-second TTL.
        let token = ConfirmToken::generate("test_secret", 1);
        // Wait for it to expire.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let token_str = token.to_string_token();
        let result = ConfirmToken::verify("test_secret", &token_str);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_token() {
        let result = ConfirmToken::verify("test_secret", "garbage");
        assert!(result.is_err());
    }
}
