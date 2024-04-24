use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::aes::Aes256;
use garble_lang::circuit::{Circuit, Gate, GateIndex};
use itertools::iproduct;
use crate::garbler::GateType::{INTERNAL, OUTPUT};

use crate::util::AESNoncePair;

pub struct GarbledCircuit {
    pub input_gates: Vec<usize>,
    pub output_gates: Vec<usize>,
    pub wire_keys: Vec<WireKeyPair>,
    pub gates: Vec<GarbledGate>
}


#[derive(Debug)]
struct GarbleOutput {
    key_output: Option<AESNoncePair>,
    value_output: Option<Vec<u8>>
}

#[derive(Debug)]
pub struct WireKeyPair {
    zero_key: AESNoncePair,
    one_key: AESNoncePair
}

impl WireKeyPair {
    pub fn new() -> WireKeyPair {
        WireKeyPair {
            zero_key: AESNoncePair::new(),
            one_key: AESNoncePair::new()
        }
    }

    pub fn get(&self, choice: usize) -> AESNoncePair {
        if choice != 0 {
            self.one_key
        } else {
            self.zero_key
        }
    }
}

#[derive(Debug)]
pub enum GateType {
    INTERNAL,
    OUTPUT
}

#[derive(Debug)]
pub struct GarbledGate {
    pub output_wire: usize,
    pub gate: Gate,
    pub key_table: Vec<Vec<u8>>,
    pub gate_type: GateType,
    pub value_table: Vec<Vec<u8>>
}

pub fn garble_circuit(circuit: &Circuit) -> GarbledCircuit {
    let mut wire_keys = Vec::new();
    let input_length: usize = circuit.input_gates.iter().sum();
    println!("{:?}", circuit.gates.len());
    for _ in 0..input_length {
        wire_keys.push(WireKeyPair::new());
    }
    for _ in 0..circuit.gates.len() {
        wire_keys.push(WireKeyPair::new());
    }

    let mut garbled_gates = Vec::new();

    // Garble tables
    for (idx, gate) in circuit.gates.iter().enumerate() {

        let mut output_key_table = Vec::new();
        let mut output_value_table = Vec::new();
        let a_wire;
        let b_wire;
        let output_wire = idx + input_length;

        let mut gate_type = INTERNAL;
        if circuit.output_gates.contains(&output_wire) {
            gate_type = OUTPUT
        }

        match gate {
            Gate::Xor(a, b) => {
                a_wire = a;
                b_wire = Some(b);
            }
            Gate::And(a, b) => {
                a_wire = a;
                b_wire = Some(b);
            }
            Gate::Not(a) => {
                a_wire = a;
                b_wire = None
            }
        }

        match gate {
            Gate::Not(_) => {
                let inputs = vec![0u8, 1u8];
                for input in inputs {
                    let input_key = wire_keys.get(*a_wire).unwrap().get(input as usize);
                    let output_val = input ^ 1u8;
                    let out_key = wire_keys.get(output_wire).unwrap().get(output_val as usize);
                    let input_cipher = Aes256Gcm::new(&input_key.key);
                    let key_bytes = out_key.key.as_slice();
                    let nonce_bytes = out_key.nonce.as_slice();
                    let mut key_output = key_bytes.to_vec();
                    key_output.extend_from_slice(nonce_bytes);
                    let ciphertext = input_cipher.encrypt(&input_key.nonce, key_output.as_slice()).unwrap();
                    output_key_table.push(ciphertext);
                    if circuit.output_gates.contains(&output_wire) {
                        let value_output = vec![output_val];
                        output_value_table.push(input_cipher.encrypt(&input_key.nonce, value_output.as_slice()).unwrap());
                    }
                }
            },
            _ => {
                let inputs: Vec<(u8, u8)> = iproduct!(0..2u8, 0..2u8).collect();
                for (val_a, val_b) in inputs {
                    let a_key = wire_keys.get(*a_wire).unwrap().get(val_a as usize);
                    let b_key = wire_keys.get(*b_wire.unwrap()).unwrap().get(val_b as usize);
                    let output_val;
                    if matches!(gate, Gate::Xor(_, _)) {
                        output_val = val_a ^ val_b
                    } else {
                        output_val = val_a & val_b
                    }
                    let out_key = wire_keys.get(output_wire).unwrap().get(output_val as usize);

                    let b_cipher = Aes256Gcm::new(&b_key.key);
                    let key_bytes = out_key.key.as_slice();
                    let nonce_bytes = out_key.nonce.as_slice();
                    let mut key_output = key_bytes.to_vec();
                    key_output.extend_from_slice(nonce_bytes);
                    let inner_ciphertext = b_cipher.encrypt(&b_key.nonce, key_output.as_slice()).unwrap();
                    let a_cipher = Aes256Gcm::new(&a_key.key);
                    let outer_ciphertext = a_cipher.encrypt(&a_key.nonce,inner_ciphertext.as_slice()).unwrap();
                    output_key_table.push(outer_ciphertext);
                    if circuit.output_gates.contains(&output_wire) {
                        let value_output = vec![output_val];
                        let inner_ciphertext = b_cipher.encrypt(&b_key.nonce, value_output.as_slice()).unwrap();
                        let a_cipher = Aes256Gcm::new(&a_key.key);
                        let outer_ciphertext = a_cipher.encrypt(&a_key.nonce,inner_ciphertext.as_slice()).unwrap(); //TODO: Use different keys for val and not val
                        output_value_table.push(outer_ciphertext)
                    }
                }
            }
        }
        garbled_gates.push(GarbledGate {
            output_wire,
            gate: gate.clone(),
            key_table: output_key_table,
            value_table: output_value_table,
            gate_type
        })
    }
    return GarbledCircuit {
        input_gates: circuit.input_gates.clone(),
        wire_keys,
        gates: garbled_gates,
        output_gates: circuit.output_gates.clone()
    }

}