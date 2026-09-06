use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use pkcs8::{DecodePrivateKey, SecretDocument};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{config::SigningAlgorithm, error::AppError};

#[derive(Clone)]
pub struct KeyMaterial {
    pub kid: String,
    pub encoding_key: Arc<EncodingKey>,
    pub algorithm: Algorithm,
    pub jwk: Jwk,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    #[serde(rename = "use")]
    pub key_use: String,
    pub alg: String,
    pub kid: String,
    #[serde(flatten)]
    pub public_key: JwkPublicKey,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kty")]
pub enum JwkPublicKey {
    #[serde(rename = "RSA")]
    Rsa { n: String, e: String },
    #[serde(rename = "EC")]
    Ec { crv: String, x: String, y: String },
}

impl KeyMaterial {
    pub fn header(&self) -> Header {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        header
    }
}

pub fn load_signing_key(
    path: &std::path::Path,
    algorithm: SigningAlgorithm,
) -> Result<KeyMaterial, AppError> {
    let pem = std::fs::read_to_string(path)?;
    match algorithm {
        SigningAlgorithm::RS256 | SigningAlgorithm::PS256 => load_rsa_key(&pem, algorithm),
        SigningAlgorithm::ES256 => load_ec_key(&pem),
    }
}

fn load_rsa_key(pem: &str, algorithm: SigningAlgorithm) -> Result<KeyMaterial, AppError> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|err| {
        AppError::Crypto(format!(
            "{} requires a PKCS#8 RSA private key: {err}",
            algorithm.as_str()
        ))
    })?;
    if algorithm == SigningAlgorithm::PS256 && private_key.n().bits() < 2048 {
        return Err(AppError::Crypto(
            "PS256 requires an RSA key of at least 2048 bits".into(),
        ));
    }
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|err| AppError::Crypto(format!("failed to load encoding key: {err}")))?;
    let modulus = private_key.n().to_bytes_be();
    let exponent = private_key.e().to_bytes_be();
    let kid = build_kid(&modulus);
    let jwk = Jwk {
        key_use: "sig".to_string(),
        alg: algorithm.as_str().to_string(),
        kid: kid.clone(),
        public_key: JwkPublicKey::Rsa {
            n: URL_SAFE_NO_PAD.encode(modulus),
            e: URL_SAFE_NO_PAD.encode(exponent),
        },
    };
    Ok(KeyMaterial {
        kid,
        encoding_key: Arc::new(encoding_key),
        algorithm: algorithm.jwt_algorithm(),
        jwk,
    })
}

fn load_ec_key(pem: &str) -> Result<KeyMaterial, AppError> {
    let (label, document) = SecretDocument::from_pem(pem).map_err(|err| {
        AppError::Crypto(format!("ES256 requires a PKCS#8 P-256 private key: {err}"))
    })?;
    if label != "PRIVATE KEY" {
        return Err(AppError::Crypto(
            "ES256 requires a PKCS#8 P-256 private key (PRIVATE KEY PEM block)".into(),
        ));
    }
    let private_key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        document.as_bytes(),
        &SystemRandom::new(),
    )
    .map_err(|err| AppError::Crypto(format!("ES256 requires a PKCS#8 P-256 private key: {err}")))?;
    // ring exposes an uncompressed P-256 point: 0x04 followed by 32-byte x and y.
    let public_key = private_key.public_key().as_ref();
    let kid = build_kid(public_key);
    let jwk = Jwk {
        key_use: "sig".to_string(),
        alg: "ES256".to_string(),
        kid: kid.clone(),
        public_key: JwkPublicKey::Ec {
            crv: "P-256".to_string(),
            x: URL_SAFE_NO_PAD.encode(&public_key[1..33]),
            y: URL_SAFE_NO_PAD.encode(&public_key[33..]),
        },
    };
    Ok(KeyMaterial {
        kid,
        encoding_key: Arc::new(EncodingKey::from_ec_der(document.as_bytes())),
        algorithm: Algorithm::ES256,
        jwk,
    })
}

fn build_kid(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    URL_SAFE_NO_PAD.encode(digest)
}
