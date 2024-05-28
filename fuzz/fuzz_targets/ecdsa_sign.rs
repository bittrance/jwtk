#![no_main]

use jwtk::{ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey}, SigningKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let alg = EcdsaAlgorithm::ES256;
    let key = EcdsaPrivateKey::generate(alg).unwrap();
    let _ = key.sign(data);
});