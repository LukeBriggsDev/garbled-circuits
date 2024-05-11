use std::fs;
use std::time::Instant;

use garble_lang::compile;

use crate::mpc::OTEval;

mod mpc;
mod util;
mod evaluator;
mod garbler;
mod oblivious;

fn main() {
    let code = fs::read_to_string("/Users/luke/Documents/University/Year 4/CSC8498 Dissertation/oblivious/src/millionaire.garble.rs").expect("FILE NOT FOUND");
    let prg = compile(code.as_str()).map_err(|e| e.prettify(&code)).unwrap();
    let x = prg.parse_arg(0, "99u8").unwrap().as_bits();
    let y = prg.parse_arg(1, "37u8").unwrap().as_bits();

    let test = prg.circuit.eval(&[x.clone(), y.clone()]);
    let now = Instant::now();
    println!("{:?}", prg.circuit.gates);
    println!("{:?}", prg.circuit.input_gates);
    println!("{:?}", prg.circuit.output_gates);
    let output = prg.circuit.ot_eval(&[x.clone(), y.clone()]);
    let elapsed = now.elapsed();
    println!("Time Elapsed: {:?}", elapsed);
    let result = prg.parse_output(&output);
    let test_result = prg.parse_output(&test);
    println!("{}", result.unwrap().to_string());
    println!("TARGET: {}", test_result.unwrap().to_string())
}
