use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, Nonce, OsRng};
use garble_lang::circuit::Circuit;
use kyber_pke;
use kyber_pke::ct_len;
use pqc_kyber::KYBER_PUBLICKEYBYTES;
use rand::Rng;
use crate::evaluator::evaluate;

use crate::garbler::{garble_circuit};
use crate::util::{AESNoncePair, xor_vec};


fn oblivious(messages: (Vec<u8>, Vec<u8>), choice: bool) {
    // Receiver
    let (pub_key, priv_key) = kyber_pke::pke_keypair().unwrap();

    let nonce: [u8; 32] = OsRng.gen();
    let nonce_pair = AESNoncePair::new();
    let pair_bytes = [nonce_pair.key.as_slice(), nonce_pair.nonce.as_slice()].concat();
    let c_bit = kyber_pke::encrypt(pub_key, pair_bytes, nonce).unwrap();
    let mut c_other = Vec::new();
    for _ in 0..c_bit.len()-8 {
        c_other.push(OsRng.gen())
    }
    for i in c_bit.len()-8..c_bit.len() {
        c_other.push(c_bit[i])
    }

    let mut enc = match choice {
        false => {(c_bit, c_other)}
        true => {(c_other, c_bit)}
    };

    // Sender
    let s = vec![
        kyber_pke::decrypt(priv_key, enc.0).unwrap(),
        kyber_pke::decrypt(priv_key, enc.1).unwrap()
    ];

    let mut ret = Vec::new();
    for (idx, plaintext) in s.iter().enumerate() {
        let key = Key::<Aes256Gcm>::from_slice(&s[idx][..32]);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&s[idx][32..]);
        let cipher = Aes256Gcm::new(&key);
        match idx {
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
    let mut result = Vec::new();
    let cipher = Aes256Gcm::new(&nonce_pair.key);
    for ciphertext in ret {
        result.push(cipher.decrypt(&nonce_pair.nonce, ciphertext.as_ref()));

    }

    println!("{:?}", result);

}

pub trait OTEval {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool>;
}

impl OTEval for Circuit {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        oblivious(([0u8;32].to_vec(), [1u8;32].to_vec()), false);
        let garbled_circuit = garble_circuit(self);
        let result = evaluate(&garbled_circuit, inputs);

        result.iter().map(|&x| if x != 0 {true} else {false}).collect()
    }
}