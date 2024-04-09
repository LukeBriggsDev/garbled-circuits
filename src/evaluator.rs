use aes_gcm::{Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::Aead;

use crate::util::AESNoncePair;

pub struct Evaluator {
    outputs: Vec<Vec<u8>>,
    pub choice: u8,
    choice_key: AESNoncePair,
    garble_key: AESNoncePair,
}

impl Evaluator {
    pub fn new() -> Evaluator {
        Evaluator {
            outputs: vec![],
            choice: 0,
            choice_key: AESNoncePair::new(),
            garble_key: AESNoncePair::new(),
        }
    }

    pub fn set_garbled_outputs(&mut self, outputs: Vec<Vec<u8>>) {
        self.outputs = outputs;
    }
    pub fn set_garble_key(&mut self, garble_key: AESNoncePair) {
        self.garble_key = garble_key;
    }
    pub fn set_choice_key(&mut self, choice_key: AESNoncePair) {
        self.choice_key = choice_key
    }

    pub fn decrypt_outputs(&self) {
        for output in &self.outputs {
            let key: Vec<u8> = self.garble_key.key.as_slice().iter()
                .zip(self.choice_key.key.as_slice().iter())
                .map(|(&key1, &key2)| key1 ^ key2)
                .collect();
            let cipher_bob = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
            let decrypt_a = cipher_bob.decrypt(&self.garble_key.nonce, output.as_slice());
            match decrypt_a {
                Ok(message) => {
                    println!("{:?}", message.as_slice())
                }
                Err(message) => {
                    println!("{}", message)
                }
            }
        }
    }
}