/// RSASSA-PKCS1-v1_5 using SHA-256.
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer, Verifier},
};
use smallvec::SmallVec;

use crate::{jwk::Jwk, url_safe_trailing_bits, Error, Result, SigningKey, VerificationKey};

/// RSA signature algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
}

impl RsaAlgorithm {
    fn is_pss(self) -> bool {
        matches!(
            self,
            RsaAlgorithm::PS256 | RsaAlgorithm::PS384 | RsaAlgorithm::PS512
        )
    }

    fn digest(self) -> MessageDigest {
        use RsaAlgorithm::*;
        match self {
            RS256 | PS256 => MessageDigest::sha256(),
            RS384 | PS384 => MessageDigest::sha384(),
            RS512 | PS512 => MessageDigest::sha512(),
        }
    }

    fn name(self) -> &'static str {
        use RsaAlgorithm::*;
        match self {
            RS256 => "RS256",
            RS384 => "RS384",
            RS512 => "RS512",
            PS256 => "PS256",
            PS384 => "PS384",
            PS512 => "PS512",
        }
    }

    pub(crate) fn from_name(name: &str) -> Result<Self> {
        Ok(match name {
            "RS256" => RsaAlgorithm::RS256,
            "RS384" => RsaAlgorithm::RS384,
            "RS512" => RsaAlgorithm::RS512,
            "PS256" => RsaAlgorithm::PS256,
            "PS384" => RsaAlgorithm::PS384,
            "PS512" => RsaAlgorithm::PS512,
            _ => return Err(Error::UnsupportedOrInvalidKey),
        })
    }
}

/// RSA Private Key.
#[derive(Debug)]
pub struct RsaPrivateKey {
    private_key: PKey<Private>,
    algorithm: RsaAlgorithm,
}

impl RsaPrivateKey {
    /// bits >= 2048.
    pub fn generate(bits: u32, algorithm: RsaAlgorithm) -> Result<Self> {
        if bits < 2048 {
            return Err(Error::UnsupportedOrInvalidKey);
        }

        Ok(Self {
            private_key: PKey::from_rsa(Rsa::generate(bits)?)?,
            algorithm,
        })
    }

    pub(crate) fn from_pkey(pkey: PKey<Private>, algorithm: RsaAlgorithm) -> Result<Self> {
        if !pkey.rsa()?.check_key()? {
            return Err(Error::UnsupportedOrInvalidKey);
        }
        Ok(Self {
            private_key: pkey,
            algorithm,
        })
    }

    pub fn from_pem(pem: &[u8], algorithm: RsaAlgorithm) -> Result<Self> {
        let pk = PKey::private_key_from_pem(pem)?;
        Self::from_pkey(pk, algorithm)
    }

    pub fn private_key_to_pem_pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.private_key_to_pem_pkcs8()?)
    }

    pub fn public_key_pem(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.public_key_to_pem()?)
    }

    pub fn public_key_pem_pkcs1(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.rsa()?.public_key_to_pem_pkcs1()?)
    }

    pub fn n(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.rsa()?.n().to_vec())
    }

    pub fn e(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.rsa()?.e().to_vec())
    }

    pub fn to_public_any(&self) -> Result<RsaAnyPublicKey> {
        // Can't figure out how to do this without going through DER/PEM...
        let pub_pem = self.public_key_pem_pkcs1()?;
        RsaAnyPublicKey::from_pem(&pub_pem)
    }
}

/// RSA Public Key that can verify signatures generated by ANY RSA algorithm.
#[derive(Debug)]
pub struct RsaAnyPublicKey {
    public_key: PKey<Public>,
}

impl RsaAnyPublicKey {
    pub(crate) fn from_pkey(pkey: PKey<Public>) -> Self {
        Self { public_key: pkey }
    }

    /// Both `BEGIN PUBLIC KEY` and `BEGIN RSA PUBLIC KEY` are OK.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(
            if std::str::from_utf8(pem).map_or(false, |pem| pem.contains("BEGIN RSA")) {
                let rsa = Rsa::public_key_from_pem_pkcs1(pem)?;
                Self::from_pkey(PKey::from_rsa(rsa)?)
            } else {
                let pkey = PKey::public_key_from_pem(pem)?;
                Self::from_pkey(pkey)
            },
        )
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self> {
        let rsa = Rsa::from_public_components(BigNum::from_slice(n)?, BigNum::from_slice(e)?)?;
        Ok(Self {
            public_key: PKey::from_rsa(rsa)?,
        })
    }

    /// BEGIN PUBLIC KEY
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.public_key_to_pem()?)
    }

    /// BEGIN RSA PUBLIC KEY
    pub fn to_pem_pkcs1(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.rsa()?.public_key_to_pem_pkcs1()?)
    }

    pub fn n(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.rsa()?.n().to_vec())
    }

    pub fn e(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.rsa()?.e().to_vec())
    }
}

/// RSA Public Key that can only verify signatures generated by one algorithm.
#[derive(Debug)]
pub struct RsaPublicKey {
    public_key: PKey<Public>,
    algorithm: RsaAlgorithm,
}

impl RsaPublicKey {
    pub(crate) fn from_pkey(pkey: PKey<Public>, algorithm: RsaAlgorithm) -> Result<Self> {
        pkey.rsa()?;
        Ok(Self {
            public_key: pkey,
            algorithm,
        })
    }

    /// Both `BEGIN PUBLIC KEY` and `BEGIN RSA PUBLIC KEY` are OK.
    pub fn from_pem(pem: &[u8], algorithm: RsaAlgorithm) -> Result<Self> {
        if std::str::from_utf8(pem).map_or(false, |pem| pem.contains("BEGIN RSA")) {
            let rsa = Rsa::public_key_from_pem_pkcs1(pem)?;
            Self::from_pkey(PKey::from_rsa(rsa)?, algorithm)
        } else {
            let pkey = PKey::public_key_from_pem(pem)?;
            Self::from_pkey(pkey, algorithm)
        }
    }

    pub fn from_components(n: &[u8], e: &[u8], algorithm: RsaAlgorithm) -> Result<Self> {
        let rsa = Rsa::from_public_components(BigNum::from_slice(n)?, BigNum::from_slice(e)?)?;
        Ok(Self {
            public_key: PKey::from_rsa(rsa)?,
            algorithm,
        })
    }

    /// BEGIN PUBLIC KEY
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.public_key_to_pem()?)
    }

    /// BEGIN RSA PUBLIC KEY
    pub fn to_pem_pkcs1(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.rsa()?.public_key_to_pem_pkcs1()?)
    }

    pub fn n(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.rsa()?.n().to_vec())
    }

    pub fn e(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.rsa()?.e().to_vec())
    }
}

impl SigningKey for RsaPrivateKey {
    fn sign(&self, v: &[u8]) -> Result<SmallVec<[u8; 64]>> {
        let mut signer = Signer::new(self.algorithm.digest(), self.private_key.as_ref())?;
        if self.algorithm.is_pss() {
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }

        signer.update(v)?;
        Ok(signer.sign_to_vec()?.into())
    }
    fn public_key_to_jwk(&self) -> Result<Jwk> {
        Ok(Jwk {
            kty: "RSA".into(),
            alg: Some(self.algorithm.name().into()),
            use_: Some("sig".into()),
            n: Some(base64::encode_config(self.n()?, url_safe_trailing_bits())),
            e: Some(base64::encode_config(self.e()?, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }

    fn alg(&self) -> &'static str {
        self.algorithm.name()
    }
}

impl VerificationKey for RsaPrivateKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        if alg != self.algorithm.name() {
            return Err(Error::VerificationError);
        }

        let mut verifier = Verifier::new(self.algorithm.digest(), self.private_key.as_ref())?;
        if self.algorithm.is_pss() {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        if verifier.verify_oneshot(sig, v)? {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }

    fn public_key_to_jwk(&self) -> Result<Jwk> {
        Ok(Jwk {
            kty: "RSA".into(),
            alg: Some(self.algorithm.name().into()),
            use_: Some("sig".into()),
            n: Some(base64::encode_config(self.n()?, url_safe_trailing_bits())),
            e: Some(base64::encode_config(self.e()?, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

impl VerificationKey for RsaPublicKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        if alg != self.algorithm.name() {
            return Err(Error::VerificationError);
        }

        let mut verifier = Verifier::new(self.algorithm.digest(), self.public_key.as_ref())?;
        if self.algorithm.is_pss() {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        if verifier.verify_oneshot(sig, v)? {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }

    fn public_key_to_jwk(&self) -> Result<Jwk> {
        Ok(Jwk {
            kty: "RSA".into(),
            alg: Some(self.algorithm.name().into()),
            use_: Some("sig".into()),
            n: Some(base64::encode_config(self.n()?, url_safe_trailing_bits())),
            e: Some(base64::encode_config(self.e()?, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

impl VerificationKey for RsaAnyPublicKey {
    fn verify(&self, v: &[u8], sig: &[u8], alg: &str) -> Result<()> {
        let alg: RsaAlgorithm = RsaAlgorithm::from_name(alg)?;

        let mut verifier = Verifier::new(alg.digest(), self.public_key.as_ref())?;
        if alg.is_pss() {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        if verifier.verify_oneshot(sig, v)? {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }

    fn public_key_to_jwk(&self) -> Result<Jwk> {
        Ok(Jwk {
            kty: "RSA".into(),
            use_: Some("sig".into()),
            n: Some(base64::encode_config(self.n()?, url_safe_trailing_bits())),
            e: Some(base64::encode_config(self.e()?, url_safe_trailing_bits())),
            ..Jwk::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ecdsa::{EcdsaAlgorithm, EcdsaPrivateKey};

    use super::*;

    #[test]
    fn conversion() -> Result<()> {
        let k = RsaPrivateKey::generate(2048, RsaAlgorithm::PS384)?;
        let pem = k.private_key_to_pem_pkcs8()?;
        RsaPrivateKey::from_pem(&pem, RsaAlgorithm::PS384)?;

        let es256key_pem =
            EcdsaPrivateKey::generate(EcdsaAlgorithm::ES256)?.private_key_to_pem_pkcs8()?;
        assert!(RsaPrivateKey::from_pem(&es256key_pem, RsaAlgorithm::PS384).is_err());

        let pk_pem = k.public_key_pem()?;
        let pk_pem_pkcs1 = k.public_key_pem_pkcs1()?;

        let pk = RsaPublicKey::from_pem(&pk_pem, RsaAlgorithm::PS384)?;
        let pk1 = RsaPublicKey::from_pem(&pk_pem_pkcs1, RsaAlgorithm::PS384)?;

        println!("pk: {:?}", pk);

        let pk_pem1 = pk1.to_pem()?;
        let pk_pem_pkcs1_1 = pk.to_pem_pkcs1()?;

        assert_eq!(pk_pem, pk_pem1);
        assert_eq!(pk_pem_pkcs1, pk_pem_pkcs1_1);

        assert_eq!(k.alg(), "PS384");

        SigningKey::public_key_to_jwk(&k)?.to_verification_key()?;
        pk.public_key_to_jwk()?;

        Ok(())
    }

    #[test]
    fn sign_verify() -> Result<()> {
        for alg in std::array::IntoIter::new([
            RsaAlgorithm::RS256,
            RsaAlgorithm::RS384,
            RsaAlgorithm::RS512,
            RsaAlgorithm::PS256,
            RsaAlgorithm::PS384,
            RsaAlgorithm::PS512,
        ]) {
            let k = RsaPrivateKey::generate(2048, alg)?;
            let pk = RsaPublicKey::from_pem(&k.public_key_pem()?, alg)?;
            let sig = k.sign(b"...")?;
            assert!(k.verify(b"...", &sig, alg.name()).is_ok());
            assert!(k.verify(b"...", &sig, "WRONG ALG").is_err());
            assert!(k.verify(b"....", &sig, alg.name()).is_err());
            assert!(pk.verify(b"...", &sig, alg.name()).is_ok());
            assert!(pk.verify(b"....", &sig, alg.name()).is_err());
        }
        Ok(())
    }
}
