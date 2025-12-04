//! Encryption module for user configuration data.
//!
//! Uses a master key + per-user key derivation approach with XChaCha20-Poly1305.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Errors that can occur during encryption/decryption
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Invalid master key: must be 32 bytes (64 hex chars or 44 base64 chars)")]
    InvalidMasterKey,
}

/// Master encryption key loaded from environment or file
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Load master key from environment variable LOGBOOK_SYNC_MASTER_KEY
    /// Accepts hex (64 chars) or base64 (44 chars) encoding
    pub fn from_env() -> Result<Self, CryptoError> {
        let key_str =
            std::env::var("LOGBOOK_SYNC_MASTER_KEY").map_err(|_| CryptoError::InvalidMasterKey)?;
        Self::from_string(&key_str)
    }

    /// Load master key from a file (first line, trimmed)
    pub fn from_file(path: &std::path::Path) -> Result<Self, CryptoError> {
        let content = std::fs::read_to_string(path).map_err(|_| CryptoError::InvalidMasterKey)?;
        let key_str = content.lines().next().unwrap_or("").trim();
        Self::from_string(key_str)
    }

    /// Parse master key from hex or base64 string
    fn from_string(s: &str) -> Result<Self, CryptoError> {
        let bytes = if s.len() == 64 {
            // Hex encoded
            hex::decode(s).map_err(|_| CryptoError::InvalidMasterKey)?
        } else if s.len() == 44 && s.ends_with('=') {
            // Base64 encoded
            BASE64
                .decode(s)
                .map_err(|_| CryptoError::InvalidMasterKey)?
        } else {
            return Err(CryptoError::InvalidMasterKey);
        };

        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidMasterKey)?;
        Ok(Self(key))
    }

    /// Generate a new random master key (for initial setup)
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Export as base64 string
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    /// Export as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get raw bytes (for HMAC signing)
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Per-user encryption context
pub struct UserCrypto {
    cipher: XChaCha20Poly1305,
}

impl UserCrypto {
    /// Derive a per-user encryption key from the master key
    pub fn derive(
        master_key: &MasterKey,
        user_id: i64,
        user_salt: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        // Combine master key with user ID for domain separation
        let mut ikm = Vec::with_capacity(40);
        ikm.extend_from_slice(&master_key.0);
        ikm.extend_from_slice(&user_id.to_le_bytes());

        // Use Argon2id for key derivation
        let params = Params::new(
            64 * 1024, // 64 MB memory
            3,         // 3 iterations
            1,         // 1 parallel lane
            Some(32),  // 32 byte output
        )
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(&ikm, user_salt, &mut derived_key)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        let cipher = XChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        Ok(Self { cipher })
    }

    /// Encrypt data, returning base64-encoded ciphertext (nonce prepended)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, CryptoError> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext and encode
        let mut combined = Vec::with_capacity(24 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(combined))
    }

    /// Decrypt base64-encoded ciphertext (with prepended nonce)
    pub fn decrypt(&self, encoded: &str) -> Result<Vec<u8>, CryptoError> {
        let combined = BASE64
            .decode(encoded)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        if combined.len() < 24 {
            return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt a serializable value as JSON
    pub fn encrypt_json<T: serde::Serialize>(&self, value: &T) -> Result<String, CryptoError> {
        let json =
            serde_json::to_vec(value).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        self.encrypt(&json)
    }

    /// Decrypt and deserialize JSON
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        encoded: &str,
    ) -> Result<T, CryptoError> {
        let plaintext = self.decrypt(encoded)?;
        serde_json::from_slice(&plaintext).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

/// Generate a random 32-byte salt for a new user
pub fn generate_user_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master_key = MasterKey::generate();
        let salt = generate_user_salt();
        let crypto = UserCrypto::derive(&master_key, 1, &salt).unwrap();

        let plaintext = b"my-secret-api-key";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_different_users_different_keys() {
        let master_key = MasterKey::generate();
        let salt1 = generate_user_salt();
        let salt2 = generate_user_salt();

        let crypto1 = UserCrypto::derive(&master_key, 1, &salt1).unwrap();
        let crypto2 = UserCrypto::derive(&master_key, 2, &salt2).unwrap();

        let encrypted = crypto1.encrypt(b"secret").unwrap();

        // User 2 cannot decrypt User 1's data
        assert!(crypto2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_master_key_serialization() {
        let key = MasterKey::generate();
        let base64 = key.to_base64();
        let hex = key.to_hex();

        assert_eq!(base64.len(), 44);
        assert_eq!(hex.len(), 64);

        // Roundtrip through base64
        let restored = MasterKey::from_string(&base64).unwrap();
        assert_eq!(key.0, restored.0);

        // Roundtrip through hex
        let restored = MasterKey::from_string(&hex).unwrap();
        assert_eq!(key.0, restored.0);
    }

    #[test]
    fn test_json_encrypt_decrypt() {
        let master_key = MasterKey::generate();
        let salt = generate_user_salt();
        let crypto = UserCrypto::derive(&master_key, 1, &salt).unwrap();

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct TestConfig {
            api_key: String,
            enabled: bool,
        }

        let config = TestConfig {
            api_key: "secret-key-123".to_string(),
            enabled: true,
        };

        let encrypted = crypto.encrypt_json(&config).unwrap();
        let decrypted: TestConfig = crypto.decrypt_json(&encrypted).unwrap();

        assert_eq!(config, decrypted);
    }
}
