use std::time::Instant;
use garble_lang::circuit::Circuit;

use crate::evaluator::evaluate;
use crate::garbler::garble_circuit;

pub trait OTEval {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool>;
}

impl OTEval for Circuit {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        let garble_start = Instant::now();
        let garbled_circuit = garble_circuit(self);
        let garble_elapsed = garble_start.elapsed();
        println!("Garble time: {:?}", garble_elapsed);
        let evaluate_start = Instant::now();
        let result = evaluate(&garbled_circuit, inputs);
        let evaluate_elapsed = evaluate_start.elapsed();
        println!("Evaluate time: {:?}", evaluate_elapsed);

        result.iter().map(|&x| if x != 0 { true } else { false }).collect()
    }
}