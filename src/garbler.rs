use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::aes::Aes256;
use garble_lang::circuit::{Circuit, Gate, GateIndex};
use itertools::iproduct;
use crate::garbler::GarbleOutput::{KeyOutput, ValueOutput};
use crate::garbler::GateType::{INTERNAL, OUTPUT};

use crate::util::AESNoncePair;

struct WireKeyPair {
    zero_key: AESNoncePair,
    one_key: AESNoncePair
}

#[derive(Debug)]
enum GarbleOutput {
    KeyOutput(AESNoncePair),
    ValueOutput(u8)
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
    garble_table: Vec<Vec<u8>>,
    gate_type: GateType
}

pub fn garble_circuit(circuit: &Circuit) -> Vec<GarbledGate> {
    let mut wire_keys = Vec::new();
    let input_length: usize = circuit.input_gates.iter().sum();
    for _ in 0..input_length {
        wire_keys.push(WireKeyPair::new());
    }
    for _ in 0..circuit.gates.len() {
        wire_keys.push(WireKeyPair::new());
    }

    let mut garbled_gates = Vec::new();

    // Garble tables
    for (idx, gate) in circuit.gates.iter().enumerate() {

        let mut garble_table = Vec::new();
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
                    let output_val = !input;
                    let out_key = wire_keys.get(output_wire).unwrap().get(output_val as usize);
                    let input_cipher = Aes256Gcm::new(&input_key.key);
                    let plaintext;
                    if circuit.output_gates.contains(&output_wire) {
                        plaintext = vec![output_val]
                    } else {
                        let key_bytes = out_key.key.as_slice();
                        let nonce_bytes = out_key.nonce.as_slice();
                        let bytes = vec![key_bytes, nonce_bytes];
                        plaintext = bytes.join((&0));
                    }
                    let ciphertext = input_cipher.encrypt(&input_key.nonce, plaintext.as_slice()).unwrap();
                    garble_table.push(ciphertext)
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
                    let plaintext;
                    if circuit.output_gates.contains(&output_wire) {
                        plaintext = vec![output_val]
                    } else {
                        let key_bytes = out_key.key.as_slice();
                        let nonce_bytes = out_key.nonce.as_slice();
                        let bytes = vec![key_bytes, nonce_bytes];
                        plaintext = bytes.join((&0));
                    }

                    let inner_ciphertext = b_cipher.encrypt(&b_key.nonce, plaintext.as_slice()).unwrap();
                    let a_cipher = Aes256Gcm::new(&a_key.key);
                    let outer_ciphertext = a_cipher.encrypt(&a_key.nonce,inner_ciphertext.as_slice()).unwrap();
                    garble_table.push(outer_ciphertext);
                }
            }
        }
        garbled_gates.push(GarbledGate {
            output_wire,
            gate: gate.clone(),
            garble_table,
            gate_type
        })
    }

    // Evaluate
    let alice_choice = 0usize;
    let bob_choice = 1usize;

    let alice_input_key = wire_keys[0].get(alice_choice);
    let bob_input_key = wire_keys[1].get(bob_choice);
    let mut wire_outputs = Vec::new();
    wire_outputs.push(KeyOutput(alice_input_key));
    wire_outputs.push(KeyOutput(bob_input_key));

    for (idx, gate) in garbled_gates.iter().enumerate() {
        let a_wire;
        let b_wire;
        println!("{:?}", gate);
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
                // for garbled_output in &gate.garble_table {
                //     let a_key = match wire_outputs[a_wire] {
                //         KeyOutput(key) => { key }
                //         ValueOutput(val) => { panic!("NOT A WIRE") }
                //     };
                //     let outer_cipher = Aes256Gcm::new(&a_key.key);
                //     let plaintext = outer_cipher.decrypt(&a_key.nonce, garbled_output.as_slice());
                //
                //}
            }
            _ => {
                for garbled_output in &gate.garble_table {
                    let a_key = match wire_outputs[a_wire] { KeyOutput(key) => {key} ValueOutput(val) => {panic!("NOT A WIRE")} };
                    let b_key = match wire_outputs[b_wire.unwrap()] { KeyOutput(key) => {key} ValueOutput(val) => {panic!("NOT A WIRE")} };;
                    let outer_cipher = Aes256Gcm::new(&a_key.key);
                    let inner_cipher = Aes256Gcm::new(&b_key.key);
                    let inner_ciphertext = outer_cipher.decrypt(&a_key.nonce, garbled_output.as_slice());
                    match inner_ciphertext {
                        Ok(ciphertext)=> {
                            let plaintext = inner_cipher.decrypt(&b_key.nonce, ciphertext.as_slice());
                            match plaintext {
                                Ok(output) => {
                                    if output.len() == 1 {
                                        wire_outputs.push(ValueOutput(output[0]));
                                    } else {
                                        let out_key = &output[0..32].iter().as_slice();
                                        let out_nonce = &output[32..];
                                        let key_pair = AESNoncePair {
                                            key: *Key::<Aes256Gcm>::from_slice(out_key),
                                            nonce: *Nonce::<Aes256Gcm>::from_slice(out_nonce),
                                        };
                                        wire_outputs.push(KeyOutput(key_pair))
                                    }

                                }
                                Err(err) => {
                                    println!("{}", err)
                                }
                            }
                        }
                        Err(err) => {
                            println!("{}", err)
                        }
                    }

                }

            }
        }
    }
    for output in wire_outputs {
        println!("{:?}", output);
    }
    return garbled_gates;
}