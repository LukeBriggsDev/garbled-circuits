use aes_gcm::{Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use garble_lang::circuit::Gate;

use crate::garbler::{GarbledCircuit, GateType};
use crate::oblivious::oblivious;
use crate::util::AESNoncePair;

pub fn evaluate(circuit: &GarbledCircuit, inputs: &[Vec<bool>]) -> Vec<u8> {
    let mut wire_outputs = Vec::new();
    let mut value_outputs = Vec::new();

    let mut key_index = 0usize;
    // Input
    for (idx, input_length) in circuit.input_gates.iter().enumerate() {
        for bit in 0usize..*input_length {
            if idx == 0 {
                // Garbler Input
                wire_outputs.push(circuit.wire_keys[key_index].get(if inputs[idx][bit] { 1usize } else { 0usize }));
            } else {
                // Evaluator Input
                let oblivious_result = oblivious(
                    (circuit.wire_keys[key_index].get(0).to_vec(),
                     circuit.wire_keys[key_index].get(1).to_vec()),
                    inputs[idx][bit],
                );
                wire_outputs.push(AESNoncePair::from_slice(oblivious_result.as_slice()));
            }
            value_outputs.push(None);
            key_index += 1;
        }
    }

    for gate in &circuit.gates {
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
                for output_key in &gate.key_table {
                    let a_key = wire_outputs[a_wire];
                    let outer_cipher = Aes256Gcm::new(&a_key.key);
                    let plaintext = outer_cipher.decrypt(&a_key.nonce, output_key.as_slice());
                    match plaintext {
                        Ok(output) => {
                            let key_pair = AESNoncePair::from_slice(output.as_slice());
                            wire_outputs.push(key_pair);
                            break;
                        }
                        Err(_) => {}
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
                        Ok(ciphertext) => {
                            let plaintext = inner_cipher.decrypt(&b_key.nonce, ciphertext.as_slice());
                            match plaintext {
                                Ok(output) => {
                                    let out_key = &output[0..32];
                                    let out_nonce = &output[32..];
                                    let key_pair = AESNoncePair {
                                        key: *Key::<Aes256Gcm>::from_slice(out_key),
                                        nonce: *Nonce::<Aes256Gcm>::from_slice(out_nonce),
                                    };
                                    wire_outputs.push(key_pair);
                                    break;
                                }
                                Err(_) => {}
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        if matches!(&gate.gate_type, GateType::OUTPUT) {
            // Output values
            match gate.gate {
                Gate::Not(_) => {
                    for output_val in &gate.value_table {
                        let a_key = wire_outputs[a_wire];
                        let outer_cipher = Aes256Gcm::new(&a_key.key);
                        let plaintext = outer_cipher.decrypt(&a_key.nonce, output_val.as_slice());
                        match plaintext {
                            Ok(output) => {
                                value_outputs.push(Some(output))
                            }
                            Err(_) => {}
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
                                    Err(_) => {}
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        } else {
            value_outputs.push(None);
        }
    }
    let output: Vec<u8> = circuit.output_gates
        .iter()
        .map(|x| value_outputs[*x]
            .as_ref()
            .unwrap()[0])
        .collect();
    return output;
}