#![no_main]

use jwtk::{ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey}, VerificationKey};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    if data.len() < 64 {
        return Corpus::Reject;
    }
    let alg = EcdsaAlgorithm::ES256;
    let key = EcdsaPrivateKey::generate(alg).unwrap();
    match key.verify(data, &data[0..64], alg.name()) {
        Ok(_) => Corpus::Reject,
        Err(_) => Corpus::Keep,
    }
});