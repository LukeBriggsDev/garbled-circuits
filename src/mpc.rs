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

pub trait OTEval {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool>;
}

impl OTEval for Circuit {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        let garbled_circuit = garble_circuit(self);
        let result = evaluate(&garbled_circuit, inputs);

        result.iter().map(|&x| if x != 0 {true} else {false}).collect()
    }
}