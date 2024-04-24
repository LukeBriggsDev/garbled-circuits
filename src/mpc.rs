use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use garble_lang::circuit::Circuit;
use pqc_kyber::{decapsulate, encapsulate, keypair, PublicKey};

use crate::evaluator::Evaluator;
use crate::garbler::{garble_circuit};
use crate::util::AESNoncePair;

// fn oblivious(garbler: &Garbler, evaluator: &mut Evaluator) {
//     // Alice part a
//     let keypairs = vec![keypair(&mut OsRng).unwrap(), keypair(&mut OsRng).unwrap()];
//
//     // Bob part b
//     let public_keys:Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
//     let chosen_key = public_keys[evaluator.choice as usize];
//     let (ciphertext, bob_key) = encapsulate(chosen_key.as_slice(), &mut OsRng).unwrap();
//
//     // Alice part b
//     let symmetric_keys = keypairs.iter().map(|keypair| decapsulate(&ciphertext, keypair.secret.as_slice()).unwrap());
//     let mut cipher_list = Vec::new();
//     let mut nonce_pairs = Vec::new();
//     for (idx, key) in symmetric_keys.enumerate() {
//         let mut ciphertext = Vec::new();
//         ciphertext.extend_from_slice(garbler.get_evaluator_keys().get(idx as u8).key.as_slice());
//         ciphertext.extend_from_slice(garbler.get_evaluator_keys().get(idx as u8).nonce.as_slice());
//         let aes_key: Key<Aes256Gcm> = key.into();
//         let cipher = Aes256Gcm::new(&aes_key);
//         let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
//         let pair = AESNoncePair {
//             key: aes_key,
//             nonce: nonce
//         };
//         cipher.encrypt_in_place(&nonce, b"", &mut ciphertext);
//         cipher_list.push(ciphertext);
//         nonce_pairs.push(pair);
//     }
//
//     // Bob part c
//     let bob_key: &Key<Aes256Gcm> = &bob_key.into();
//     let cipher_bob = Aes256Gcm::new(&bob_key);
//
//     for (pair, ciphertext) in nonce_pairs.iter().zip(cipher_list) {
//         let decrypt = cipher_bob.decrypt(&pair.nonce, ciphertext.as_slice());
//         match decrypt {
//             Ok(message) => {
//                 let aes: [u8; 32] = message[..32].try_into().expect("AES INCORRECT SIZE");
//                 let nonce: [u8; 12] = message[32..].try_into().expect("NONCE INCORRECT SIZE");
//                 let aes_pair = AESNoncePair {
//                     key: aes.into(),
//                     nonce: nonce.into(),
//                 };
//                 evaluator.set_choice_key(aes_pair);
//             }
//             Err(message) => {
//                 println!("{}", message)
//             }
//         }
//     }
// }

pub trait OTEval {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool>;
}

impl OTEval for Circuit {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        garble_circuit(self, inputs).iter().map(|&x| if x != 0 {true} else {false}).collect()
        // evaluator.set_garbled_outputs(garbler.get_outputs().clone());
        // evaluator.set_garble_key(garbler.get_choice_key());
        // oblivious(&garbler, &mut evaluator);
        // evaluator.decrypt_outputs();
    }
}