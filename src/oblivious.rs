use aes_gcm::{Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, Nonce, OsRng};
use rand::Rng;

use crate::util::AESNoncePair;

pub fn oblivious(messages: (Vec<u8>, Vec<u8>), choice: bool) -> Vec<u8> {
    // Receiver
    let (pub_key, priv_key) = kyber_pke::pke_keypair().unwrap();

    let nonce: [u8; 32] = OsRng.gen();
    let nonce_pair = AESNoncePair::new();
    let pair_bytes = nonce_pair.to_vec();
    let c_bit = kyber_pke::encrypt(pub_key, pair_bytes, nonce).unwrap();
    let mut c_other = Vec::new();
    for _ in 0..c_bit.len() - 8 {
        c_other.push(OsRng.gen())
    }
    for i in c_bit.len() - 8..c_bit.len() {
        c_other.push(c_bit[i])
    }

    let enc = match choice {
        false => { (c_bit, c_other) }
        true => { (c_other, c_bit) }
    };

    // Sender
    let s = vec![
        kyber_pke::decrypt(priv_key, enc.0).unwrap(),
        kyber_pke::decrypt(priv_key, enc.1).unwrap(),
    ];

    let mut ret = Vec::new();
    for i in 0..s.len() {
        let key = Key::<Aes256Gcm>::from_slice(&s[i][..32]);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&s[i][32..]);
        let cipher = Aes256Gcm::new(&key);
        match i {
            0 => {
                ret.push(cipher.encrypt(&nonce, messages.0.as_ref()).unwrap())
            }
            1 => {
                ret.push(cipher.encrypt(&nonce, messages.1.as_ref()).unwrap())
            }
            _ => {
                panic!("TOO MANY MESSAGES")
            }
        }
    }

    // receiver
    let cipher = Aes256Gcm::new(&nonce_pair.key);
    for ciphertext in ret {
        match cipher.decrypt(&nonce_pair.nonce, ciphertext.as_ref()) {
            Ok(message) => {
                return message;
            }
            Err(_) => {
                continue;
            }
        }
    }
    panic!("NO MESSAGE DECRYPTED")
}