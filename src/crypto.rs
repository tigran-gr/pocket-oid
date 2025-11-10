use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::AppError;

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
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

impl KeyMaterial {
    pub fn header(&self) -> Header {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        header
    }
}

pub fn load_signing_key(path: &std::path::Path) -> Result<KeyMaterial, AppError> {
    let pem = std::fs::read_to_string(path)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)
        .map_err(|err| AppError::Crypto(format!("failed to parse signing key: {err}")))?;
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|err| AppError::Crypto(format!("failed to load encoding key: {err}")))?;
    let modulus = private_key.n().to_bytes_be();
    let exponent = private_key.e().to_bytes_be();
    let kid = build_kid(&modulus);
    let jwk = Jwk {
        kty: "RSA".to_string(),
        key_use: "sig".to_string(),
        alg: "RS256".to_string(),
        kid: kid.clone(),
        n: URL_SAFE_NO_PAD.encode(modulus),
        e: URL_SAFE_NO_PAD.encode(exponent),
    };
    Ok(KeyMaterial {
        kid,
        encoding_key: Arc::new(encoding_key),
        algorithm: Algorithm::RS256,
        jwk,
    })
}

fn build_kid(modulus: &[u8]) -> String {
    let digest = Sha256::digest(modulus);
    URL_SAFE_NO_PAD.encode(digest)
}
