use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Nonce, OsRng};

pub fn xor_vec(v1: Vec<u8>, v2: Vec<u8>) -> Vec<u8> {
    let v3: Vec<u8> = v1
        .iter()
        .zip(v2.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    return v3;
}

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
