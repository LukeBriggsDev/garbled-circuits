use std::fs;

use garble_lang::compile;

use crate::mpc::OTEval;
use std::env;

mod mpc;
mod util;
mod evaluator;
mod garbler;
mod oblivious;

fn main() {
    let args: Vec<String> = env::args().collect();
    let file = &args[1];
    let a = &args[2];
    let b = &args[3];
    let code = fs::read_to_string(file).expect("FILE NOT FOUND");
    let prg = compile(code.as_str()).map_err(|e| e.prettify(&code)).unwrap();
    let x = prg.parse_arg(0, a).unwrap().as_bits();
    let y = prg.parse_arg(1, b).unwrap().as_bits();

    let test = prg.circuit.eval(&[x.clone(), y.clone()]);

    println!("{:?}", prg.circuit.gates);
    println!("{:?}", prg.circuit.input_gates);
    println!("{:?}", prg.circuit.output_gates);
    let output = prg.circuit.ot_eval(&[x.clone(), y.clone()]);
    let result = prg.parse_output(&output);
    let test_result = prg.parse_output(&test);
    println!("{}", result.unwrap().to_string());
    println!("TARGET: {}", test_result.unwrap().to_string())
}
