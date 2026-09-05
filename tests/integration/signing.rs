use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, decode_header};
use pocket_oid::{app::AppState, config::SigningAlgorithm};
use serde_json::{Value, json};
use std::fs;

use crate::common::{
    SigningTestConfig, fixture_config_dir, get_json, post_token_form, verify_jwt_with_jwks,
};

#[tokio::test]
async fn es256_access_token_verifies_using_published_ec_jwk() {
    let config = SigningTestConfig::new(SigningAlgorithm::ES256);
    let app = AppState::initialize(&config.path).unwrap().router();
    let (status, discovery) = get_json(app.clone(), "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["ES256"])
    );

    let (status, jwks) = get_json(app.clone(), "/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    assert_eq!(key["alg"], "ES256");
    assert_eq!(key["use"], "sig");
    for coordinate in ["x", "y"] {
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(key[coordinate].as_str().unwrap())
                .unwrap()
                .len(),
            32
        );
    }
    for absent in ["n", "e", "d", "p", "q"] {
        assert!(key.get(absent).is_none(), "unexpected key field {absent}");
    }
    // A restart with the same key must preserve the public key identifier.
    let restarted = AppState::initialize(&config.path).unwrap();
    assert_eq!(key["kid"], restarted.signing_key.kid);

    let (status, response) = post_token_form(
        app,
        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = response["access_token"].as_str().unwrap();
    assert_eq!(decode_header(token).unwrap().alg, Algorithm::ES256);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(token.rsplit('.').next().unwrap())
            .unwrap()
            .len(),
        64
    );
    let claims = verify_jwt_with_jwks(token, &jwks);
    assert_eq!(claims["sub"], "svc-a");
    assert_eq!(claims["scope"], "default");
    assert_eq!(claims["custom"]["tenant"], "acme");
}

#[test]
fn startup_rejects_keys_that_do_not_match_the_signing_algorithm() {
    for (algorithm, key, expected) in [
        (
            SigningAlgorithm::ES256,
            fixture_config_dir("config-basic").join("keys/signing-key.pem"),
            "P-256",
        ),
        (
            SigningAlgorithm::ES256,
            fixture_config_dir("keys").join("es384.pem"),
            "P-256",
        ),
        (
            SigningAlgorithm::RS256,
            fixture_config_dir("keys").join("es256.pem"),
            "RSA",
        ),
    ] {
        let config = SigningTestConfig::new(algorithm);
        fs::copy(key, config.path.join("keys/signing-key.pem")).unwrap();
        let error = AppState::initialize(&config.path)
            .err()
            .expect("mismatched key must fail startup");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn startup_rejects_unsupported_signing_algorithms_and_invalid_ec_pem() {
    let config = SigningTestConfig::new(SigningAlgorithm::ES256);
    let provider_path = config.path.join("provider.json");
    let mut provider: Value = serde_json::from_slice(&fs::read(&provider_path).unwrap()).unwrap();
    for algorithm in ["HS256", "ES384", "PS256", "none"] {
        provider["signing_algorithm"] = json!(algorithm);
        fs::write(&provider_path, serde_json::to_vec(&provider).unwrap()).unwrap();
        assert!(
            AppState::initialize(&config.path).is_err(),
            "accepted {algorithm}"
        );
    }
    provider["signing_algorithm"] = json!("ES256");
    fs::write(&provider_path, serde_json::to_vec(&provider).unwrap()).unwrap();
    fs::write(
        config.path.join("keys/signing-key.pem"),
        "not a private key",
    )
    .unwrap();
    assert!(AppState::initialize(&config.path).is_err());
}
