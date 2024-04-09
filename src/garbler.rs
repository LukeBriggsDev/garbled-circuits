use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit};
use itertools::iproduct;

use crate::util::AESNoncePair;

#[derive(Copy, Clone)]
pub struct GarblerKeyPair {
    pub zero_key: AESNoncePair,
    pub one_key: AESNoncePair,
}

impl GarblerKeyPair {
    fn new() -> GarblerKeyPair {
        GarblerKeyPair {
            zero_key: AESNoncePair::new(),
            one_key: AESNoncePair::new(),
        }
    }
    pub fn get(&self, bit: u8) -> AESNoncePair {
        if (bit == 1) {
            self.one_key
        } else {
            self.zero_key
        }
    }
}
pub struct Garbler {
    outputs: Vec<Vec<u8>>,
    keys: Vec<GarblerKeyPair>,
    pub choice: u8,
    input: GarblerKeyPair,
}

impl Garbler {
    pub fn new() -> Garbler {
        Garbler {
            outputs: vec![],
            keys: vec![],
            choice: 0,
            input: GarblerKeyPair::new(),
        }
    }
    pub fn get_outputs(&self) -> &Vec<Vec<u8>> {
        &self.outputs
    }
    fn generate_keys(&mut self) {
        self.keys = Vec::new();
        for _ in 0..2 {
            self.keys.push(GarblerKeyPair::new())
        }
    }
    pub fn get_choice_key(&self) -> AESNoncePair {
        self.keys[0].get(self.choice)
    }
    pub fn get_evaluator_keys(&self) -> GarblerKeyPair {
        self.keys[1]
    }
    pub fn garble(&mut self) {
        self.generate_keys();
        let inputs = iproduct!(vec![0u8, 1u8].into_iter(), vec![0u8, 1u8].into_iter());
        self.outputs = Vec::new();
        for input in inputs {
            match input {
                (a, b) => {
                    let mut ciphertext = Vec::new();
                    ciphertext.push(a & b);
                    let key: Vec<u8> = self.keys[0].get(a).key.as_slice().iter()
                        .zip(self.keys[1].get(b).key.as_slice().iter())
                        .map(|(&key1, &key2)| key1 ^ key2)
                        .collect();

                    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
                    cipher.encrypt_in_place(&self.keys[0].get(a).nonce, b"", &mut ciphertext).unwrap();
                    self.outputs.push(ciphertext);
                }
            }
        }
    }
}