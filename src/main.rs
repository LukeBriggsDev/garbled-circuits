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
    let x = prg.parse_arg(0, "9i16").unwrap().as_bits();
    let y = prg.parse_arg(1, "11i16").unwrap().as_bits();

    let test = prg.circuit.eval(&[x.clone(), y.clone()]);
    let output = prg.circuit.ot_eval(&[x.clone(), y.clone()]);
    let result = prg.parse_output(&output);
    let test_result = prg.parse_output(&test);
    println!("{}", result.unwrap().to_string());
    println!("TARGET: {}", test_result.unwrap().to_string())
}
