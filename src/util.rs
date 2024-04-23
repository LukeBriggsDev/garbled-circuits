use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Nonce, OsRng};

#[derive(Copy, Clone, Debug)]
pub struct AESNoncePair {
    pub key: Key<Aes256Gcm>,
    pub nonce: Nonce<Aes256Gcm>,
}

impl AESNoncePair {
    pub fn new() -> AESNoncePair {
        AESNoncePair {
            key: Aes256Gcm::generate_key(OsRng),
            nonce: Aes256Gcm::generate_nonce(&mut OsRng),
        }
    }
}
