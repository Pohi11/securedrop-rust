//! Opaque random tokens (refresh tokens, share-link tokens).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

/// 32 bytes = 256 bits from the operating system CSPRNG, base64url-encoded (43 chars).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// What we store in the database instead of the token itself.
pub fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_url_safe() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn hash_is_deterministic_32_bytes() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_eq!(hash_token("abc").len(), 32);
        assert_ne!(hash_token("abc"), hash_token("abd"));
    }
}
