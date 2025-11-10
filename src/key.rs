use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;

use crate::config::SigningKeyConfig;

#[derive(Debug, Clone, Serialize)]
pub struct JsonWebKey {
    pub kty: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub usage: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

#[derive(Debug, Clone)]
pub struct SigningKey {
    pub id: String,
    pub algorithm: Algorithm,
    pub encoding_key: EncodingKey,
    pub jwk: JsonWebKey,
}

impl SigningKey {
    fn from_config(config: &SigningKeyConfig) -> Result<Self> {
        let pem_data = read_file(&config.private_key_path)?;
        match config.algorithm.as_str() {
            "RS256" => Self::load_rsa_key(config, &pem_data),
            other => anyhow::bail!("unsupported signing algorithm: {other}"),
        }
    }

    fn load_rsa_key(config: &SigningKeyConfig, pem_data: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(std::str::from_utf8(pem_data)?)
            .with_context(|| {
                format!(
                    "failed to parse RSA private key for signing key {}",
                    config.id
                )
            })?;
        let public_key = private_key.to_public_key();
        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();

        let n = URL_SAFE_NO_PAD.encode(n_bytes);
        let e = URL_SAFE_NO_PAD.encode(e_bytes);

        let jwk = JsonWebKey {
            kty: "RSA".to_string(),
            kid: config.id.clone(),
            usage: "sig".to_string(),
            alg: config.algorithm.clone(),
            n,
            e,
        };

        let encoding_key = EncodingKey::from_rsa_pem(pem_data).with_context(|| {
            format!("failed to build encoding key for signing key {}", config.id)
        })?;

        Ok(SigningKey {
            id: config.id.clone(),
            algorithm: Algorithm::RS256,
            encoding_key,
            jwk,
        })
    }

    pub fn sign(&self, claims: &serde_json::Value) -> Result<String> {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.id.clone());
        let token = jsonwebtoken::encode(&header, claims, &self.encoding_key)
            .with_context(|| format!("failed to sign token with key {}", self.id))?;
        Ok(token)
    }
}

#[derive(Clone)]
pub struct KeyStore {
    keys: Arc<Vec<SigningKey>>,
}

impl KeyStore {
    pub fn from_configs(configs: &[SigningKeyConfig]) -> Result<Self> {
        let mut keys = Vec::new();
        for config in configs {
            let key = SigningKey::from_config(config)?;
            keys.push(key);
        }
        if keys.is_empty() {
            anyhow::bail!("no signing keys loaded");
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    pub fn primary(&self) -> &SigningKey {
        // safe to unwrap due to constructor guarantee
        &self.keys[0]
    }

    pub fn jwks(&self) -> JsonWebKeySet {
        let keys = self.keys.iter().map(|k| k.jwk.clone()).collect();
        JsonWebKeySet { keys }
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    let data =
        fs::read(path).with_context(|| format!("failed to read key from {}", path.display()))?;
    Ok(data)
}
