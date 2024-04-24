use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::aes::Aes256;
use garble_lang::circuit::{Circuit, Gate, GateIndex};
use itertools::iproduct;
use crate::garbler::GateType::{INTERNAL, OUTPUT};

use crate::util::AESNoncePair;

#[derive(Debug)]
struct WireKeyPair {
    zero_key: AESNoncePair,
    one_key: AESNoncePair
}

#[derive(Debug)]
struct GarbleOutput {
    key_output: Option<AESNoncePair>,
    value_output: Option<Vec<u8>>
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
enum GateType {
    INTERNAL,
    OUTPUT
}

#[derive(Debug)]
pub struct GarbledGate {
    output_wire: usize,
    gate: Gate,
    key_table: Vec<Vec<u8>>,
    gate_type: GateType,
    value_table: Vec<Vec<u8>>
}

pub fn garble_circuit(circuit: &Circuit, inputs: &[Vec<bool>]) -> Vec<u8> {
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

    let mut wire_outputs = Vec::new();
    let mut value_outputs = Vec::new();

    let mut key_index = 0usize;
    // Input
    for (idx, input_length) in circuit.input_gates.iter().enumerate() {
        for bit in 0usize..*input_length {
            wire_outputs.push(wire_keys[key_index].get(if inputs[idx][bit] {1usize} else {0usize}));
            value_outputs.push(None);
            key_index += 1;
        }
    }

    for (idx, gate) in garbled_gates.iter().enumerate() {
        let a_wire;
        let b_wire;
        //let output_wire;
        match gate.gate {
            Gate::Xor(a, b) => {
                a_wire = a;
                b_wire = Some(b)
            }
            Gate::And(a, b) => {
                a_wire = a;
                b_wire = Some(b)
            }
            Gate::Not(a) => {
                a_wire = a;
                b_wire = None
            }
        }
        match gate.gate {
            Gate::Not(_) => {
                for (output_key) in &gate.key_table {
                    let a_key = wire_outputs[a_wire];
                    let outer_cipher = Aes256Gcm::new(&a_key.key);
                    let plaintext = outer_cipher.decrypt(&a_key.nonce, output_key.as_slice());
                    match plaintext {
                        Ok(output) => {
                            let out_key = &output[0..32].iter().as_slice();
                            let out_nonce = &output[32..];
                            let key_pair = AESNoncePair {
                                key: *Key::<Aes256Gcm>::from_slice(out_key),
                                nonce: *Nonce::<Aes256Gcm>::from_slice(out_nonce),
                            };
                            wire_outputs.push(key_pair)

                        }
                        Err(err) => {
                        }
                    }
                }
            }
            _ => {
                for garbled_output in &gate.key_table {
                    let a_key = wire_outputs[a_wire];
                    let b_key = wire_outputs[b_wire.unwrap()];
                    let outer_cipher = Aes256Gcm::new(&a_key.key);
                    let inner_cipher = Aes256Gcm::new(&b_key.key);
                    let inner_ciphertext = outer_cipher.decrypt(&a_key.nonce, garbled_output.as_slice());
                    match inner_ciphertext {
                        Ok(ciphertext)=> {
                            let plaintext = inner_cipher.decrypt(&b_key.nonce, ciphertext.as_slice());
                            match plaintext {
                                Ok(output) => {
                                    let out_key = &output[0..32];
                                    let out_nonce = &output[32..];
                                    let key_pair = AESNoncePair {
                                        key: *Key::<Aes256Gcm>::from_slice(out_key),
                                        nonce: *Nonce::<Aes256Gcm>::from_slice(out_nonce),
                                    };
                                    wire_outputs.push(key_pair)
                                }
                                Err(err) => {
                                }
                            }
                        }
                        Err(err) => {
                        }
                    }

                }

            }
        }
        if matches!(gate.gate_type, OUTPUT) {
            // Output values
            match gate.gate {
                Gate::Not(_) => {
                    for (output_val) in &gate.value_table {
                        let a_key = wire_outputs[a_wire];
                        let outer_cipher = Aes256Gcm::new(&a_key.key);
                        let plaintext = outer_cipher.decrypt(&a_key.nonce, output_val.as_slice());
                        match plaintext {
                            Ok(output) => {
                                value_outputs.push(Some(output))
                            }
                            Err(err) => {
                            }
                        }
                    }
                }
                _ => {
                    for garbled_output in &gate.value_table {
                        let a_key = wire_outputs[a_wire];
                        let b_key = wire_outputs[b_wire.unwrap()];
                        let outer_cipher = Aes256Gcm::new(&a_key.key);
                        let inner_cipher = Aes256Gcm::new(&b_key.key);
                        let inner_ciphertext = outer_cipher.decrypt(&a_key.nonce, garbled_output.as_slice());
                        match inner_ciphertext {
                            Ok(ciphertext) => {
                                let plaintext = inner_cipher.decrypt(&b_key.nonce, ciphertext.as_slice());
                                match plaintext {
                                    Ok(output) => {
                                        value_outputs.push(Some(output))
                                    }
                                    Err(err) => {
                                    }
                                }
                            }
                            Err(err) => {
                            }
                        }
                    }
                }
            }
        } else {
            value_outputs.push(None);
        }
    }
    let output: Vec<u8> = circuit.output_gates.iter().map(|x| value_outputs[*x].as_ref().unwrap()[0]).collect();
    return output
}