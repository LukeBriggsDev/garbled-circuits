use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::{Aead, AeadMutInPlace, OsRng};
use garble_lang::circuit::Circuit;
use itertools::{iproduct, Itertools};
use pqc_kyber::{decapsulate, encapsulate, keypair};
use rand::prelude::SliceRandom;
use std::{fs, str};
use crate::players::{AESNoncePair, Evaluator, Garbler};

fn oblivious(garbler: &Garbler, evaluator: &mut Evaluator) {
    // Alice part a
    let keypair_a = keypair(&mut OsRng).unwrap();
    let keypair_b = keypair(&mut OsRng).unwrap();

    // Bob part b
    let public_keys = vec![keypair_a.public, keypair_b.public];
    let chosen_key = public_keys[evaluator.choice as usize];
    let (ciphertext, bob_key) = encapsulate(chosen_key.as_slice(), &mut OsRng).unwrap();

    // Alice part b
    let key_a = decapsulate(&ciphertext, &keypair_a.secret).unwrap();
    let key_b = decapsulate(&ciphertext, &keypair_b.secret).unwrap();

    let mut ciphertext_a = Vec::new();
    ciphertext_a.extend_from_slice(garbler.get_evaluator_keys().zero_key.key.as_slice());
    ciphertext_a.extend_from_slice(garbler.get_evaluator_keys().zero_key.nonce.as_slice());
    let aes_key_a: &Key<Aes256Gcm> = &key_a.into();
    ;
    let cipher_a = Aes256Gcm::new(&aes_key_a);
    let nonce_a = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher_a.encrypt_in_place(&nonce_a, b"", &mut ciphertext_a);

    let mut ciphertext_b = Vec::new();
    ciphertext_b.extend_from_slice(garbler.get_evaluator_keys().one_key.key.as_slice());
    ciphertext_b.extend_from_slice(garbler.get_evaluator_keys().one_key.nonce.as_slice());
    let aes_key_b: &Key<Aes256Gcm> = &key_b.into();
    let cipher_b = Aes256Gcm::new(&aes_key_b);
    let nonce_b = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher_b.encrypt_in_place(&nonce_b, b"", &mut ciphertext_b);

    // Bob part c
    let bob_key: &Key<Aes256Gcm> = &bob_key.into();
    let cipher_bob = Aes256Gcm::new(&bob_key);
    let decrypt_a = cipher_bob.decrypt(&nonce_a, ciphertext_a.as_slice());
    match decrypt_a {
        Ok(message) => {
            let aes: [u8; 32] = message[..32].try_into().expect("AES INCORRECT SIZE");
            let nonce: [u8; 12] = message[32..].try_into().expect("NONCE INCORRECT SIZE");
            let aes_pair = AESNoncePair {
                key: aes.into(),
                nonce: nonce.into(),
            };
            evaluator.set_choice_key(aes_pair);
        }
        Err(message) => {
            println!("{}", message)
        }
    }
    let decrypt_b = cipher_bob.decrypt(&nonce_b, ciphertext_b.as_slice());
    match decrypt_b {
        Ok(message) => {
            let aes: [u8; 32] = message[..32].try_into().expect("AES INCORRECT SIZE");
            let nonce: [u8; 12] = message[32..].try_into().expect("NONCE INCORRECT SIZE");
            let aes_pair = AESNoncePair {
                key: aes.into(),
                nonce: nonce.into(),
            };
            evaluator.set_choice_key(aes_pair);
        }
        Err(message) => {
            println!("{}", message)
        }
    }
}

pub trait OTEval {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool>;
}

impl OTEval for Circuit {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        let mut garbler = Garbler::new();
        let mut evaluator = Evaluator::new();
        garbler.garble();
        evaluator.set_garbled_outputs(garbler.get_outputs().clone());
        evaluator.set_garble_key(garbler.get_choice_key());
        evaluator.choice = 0;
        oblivious(&garbler, &mut evaluator);
        evaluator.decrypt_outputs();
        Vec::new()
    }
}