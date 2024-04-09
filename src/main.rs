use std::fs;

use aes_gcm::{AeadCore, AeadInPlace, KeyInit};
use aes_gcm::aead::Aead;
use garble_lang::compile;
use pqc_kyber::*;
use rand::seq::SliceRandom;

use crate::mpc::OTEval;

mod mpc;
mod util;
mod evaluator;
mod garbler;

fn main() {
    let code = fs::read_to_string("/Users/luke/Documents/University/Year 4/CSC8498 Dissertation/oblivious/src/millionaire.garble.rs").expect("FILE NOT FOUND");
    let prg = compile(code.as_str()).map_err(|e| e.prettify(&code)).unwrap();
    let x = prg.parse_arg(0, "2u8").unwrap().as_bits();
    let y = prg.parse_arg(1, "10u8").unwrap().as_bits();

    let output = prg.circuit.ot_eval(&[x, y]);
}
