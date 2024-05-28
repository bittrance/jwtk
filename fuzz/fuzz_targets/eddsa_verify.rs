#![no_main]

use jwtk::{eddsa::Ed25519PrivateKey, VerificationKey};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    let key = Ed25519PrivateKey::generate().unwrap();
    match key.verify(data, data, "EdDSA") {
        Ok(_) => Corpus::Reject,
        Err(_) => Corpus::Keep,
    }
});