use garble_lang::circuit::Circuit;

use crate::evaluator::evaluate;
use crate::garbler::garble_circuit;

pub trait OTEval {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool>;
}

impl OTEval for Circuit {
    fn ot_eval(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        let garbled_circuit = garble_circuit(self);
        let result = evaluate(&garbled_circuit, inputs);

        result.iter().map(|&x| if x != 0 { true } else { false }).collect()
    }
}