use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, decode_header};
use pocket_oid::{app::AppState, config::SigningAlgorithm};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;

use crate::common::{
    SigningTestConfig, configure_signing_key, fixture_config_dir, get_json, post_token_form,
    verify_jwt_with_jwks,
};

fn write_clients(config: &SigningTestConfig, overrides: &[(&str, Option<SigningAlgorithm>)]) {
    let path = config.path.join("clients.json");
    let existing: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let clients: Vec<_> = overrides
        .iter()
        .map(|(id, algorithm)| {
            let mut client = existing[0].clone();
            client["client_id"] = json!(id);
            if let Some(algorithm) = algorithm {
                client["signing_algorithm"] = json!(algorithm);
            } else {
                client.as_object_mut().unwrap().remove("signing_algorithm");
            }
            client
        })
        .collect();
    fs::write(path, serde_json::to_vec_pretty(&clients).unwrap()).unwrap();
}

#[tokio::test]
async fn clients_use_independent_algorithms_and_share_a_complete_jwks() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    let original = AppState::initialize(&config.path).unwrap();
    let default_kid = original.signing_keys[&SigningAlgorithm::RS256].kid.clone();
    write_clients(
        &config,
        &[
            ("inherited", None),
            ("rsa-client", Some(SigningAlgorithm::RS256)),
            ("pss-client", Some(SigningAlgorithm::PS256)),
            ("ec-client", Some(SigningAlgorithm::ES256)),
            ("second-pss-client", Some(SigningAlgorithm::PS256)),
        ],
    );
    configure_signing_key(
        &config.path,
        SigningAlgorithm::PS256,
        &fixture_config_dir("keys").join("rsa-alternate.pem"),
    );
    configure_signing_key(
        &config.path,
        SigningAlgorithm::ES256,
        &fixture_config_dir("keys").join("es256.pem"),
    );
    let app = AppState::initialize(&config.path).unwrap().router();
    let (_, discovery) = get_json(app.clone(), "/.well-known/openid-configuration").await;
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["RS256", "ES256", "PS256"])
    );
    let (_, jwks) = get_json(app.clone(), "/jwks.json").await;
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3, "one key per algorithm, not per client");
    let kids: std::collections::BTreeSet<_> = keys
        .iter()
        .map(|key| key["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids.len(), 3);
    assert_eq!(
        keys.iter().find(|key| key["alg"] == "RS256").unwrap()["kid"],
        default_kid
    );
    let restarted = AppState::initialize(&config.path).unwrap().router();
    assert_eq!(get_json(restarted, "/jwks.json").await.1, jwks);

    let get_token = |id| {
        let app = app.clone();
        let form = format!(
            "grant_type=client_credentials&client_id={id}&client_secret=supersecret&signing_algorithm=ES256"
        );
        async move { post_token_form(app, &form).await }
    };
    // Exercise different algorithms concurrently to catch accidental shared selection.
    let (inherited, pss) = tokio::join!(get_token("inherited"), get_token("pss-client"));
    for (id, algorithm, (status, response)) in [
        ("inherited", Algorithm::RS256, inherited),
        ("pss-client", Algorithm::PS256, pss),
        (
            "rsa-client",
            Algorithm::RS256,
            get_token("rsa-client").await,
        ),
        ("ec-client", Algorithm::ES256, get_token("ec-client").await),
        (
            "second-pss-client",
            Algorithm::PS256,
            get_token("second-pss-client").await,
        ),
    ] {
        assert_eq!(status, StatusCode::OK);
        let token = response["access_token"].as_str().unwrap();
        assert_eq!(decode_header(token).unwrap().alg, algorithm, "{id}");
        assert_eq!(verify_jwt_with_jwks(token, &jwks)["sub"], id);
    }
}

#[tokio::test]
async fn clients_inherit_a_non_rs256_default_and_can_override_it_with_rs256() {
    let config = SigningTestConfig::new(SigningAlgorithm::PS256);
    write_clients(
        &config,
        &[
            ("inherited", None),
            ("rsa-client", Some(SigningAlgorithm::RS256)),
        ],
    );
    configure_signing_key(
        &config.path,
        SigningAlgorithm::RS256,
        &fixture_config_dir("keys").join("rsa-alternate.pem"),
    );
    let app = AppState::initialize(&config.path).unwrap().router();
    let (_, jwks) = get_json(app.clone(), "/jwks.json").await;
    for (id, expected) in [
        ("inherited", Algorithm::PS256),
        ("rsa-client", Algorithm::RS256),
    ] {
        let (status, response) = post_token_form(
            app.clone(),
            &format!("grant_type=client_credentials&client_id={id}&client_secret=supersecret"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = response["access_token"].as_str().unwrap();
        assert_eq!(decode_header(token).unwrap().alg, expected);
        assert_eq!(verify_jwt_with_jwks(token, &jwks)["sub"], id);
    }
}

#[test]
fn client_override_requires_a_distinct_compatible_key_at_startup() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    write_clients(&config, &[("pss-client", Some(SigningAlgorithm::PS256))]);
    let error = AppState::initialize(&config.path).err().unwrap();
    assert!(error.to_string().contains("signing_key_paths"), "{error}");
    for (file, expected) in [
        (
            fixture_config_dir("config-basic").join("keys/signing-key.pem"),
            "use distinct keys",
        ),
        (
            fixture_config_dir("keys").join("es256.pem"),
            "RSA private key",
        ),
        (
            fixture_config_dir("keys").join("rsa1024.pem"),
            "at least 2048 bits",
        ),
    ] {
        configure_signing_key(&config.path, SigningAlgorithm::PS256, &file);
        let error = AppState::initialize(&config.path).err().unwrap();
        assert!(error.to_string().contains(expected), "{error}");
    }
    fs::remove_file(config.path.join("keys/ps256.pem")).unwrap();
    let error = AppState::initialize(&config.path).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("failed to load PS256 signing key"),
        "{error}"
    );
}

#[tokio::test]
async fn disabled_clients_and_unused_key_paths_do_not_enable_algorithms() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    write_clients(
        &config,
        &[
            ("inherited", None),
            ("disabled", Some(SigningAlgorithm::ES256)),
        ],
    );
    let path = config.path.join("clients.json");
    let mut clients: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    clients[1]["enabled"] = json!(false);
    fs::write(path, serde_json::to_vec(&clients).unwrap()).unwrap();
    let path = config.path.join("provider.json");
    let mut provider: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    provider["signing_key_paths"] =
        json!({"ES256": "missing-ec-key.pem", "PS256": "missing-rsa-key.pem"});
    fs::write(path, serde_json::to_vec(&provider).unwrap()).unwrap();
    let app = AppState::initialize(&config.path).unwrap().router();
    assert_eq!(
        get_json(app.clone(), "/.well-known/openid-configuration")
            .await
            .1["id_token_signing_alg_values_supported"],
        json!(["RS256"])
    );
    assert_eq!(
        get_json(app, "/jwks.json").await.1["keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn provider_default_can_use_an_explicit_key_path() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    configure_signing_key(
        &config.path,
        SigningAlgorithm::RS256,
        &fixture_config_dir("keys").join("rsa-alternate.pem"),
    );
    fs::remove_file(config.path.join("keys/signing-key.pem")).unwrap();
    assert!(AppState::initialize(&config.path).is_ok());
}

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
    assert_eq!(
        key["kid"],
        restarted.signing_keys[&SigningAlgorithm::ES256].kid
    );

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

#[tokio::test]
async fn ps256_access_token_verifies_using_published_rsa_jwk_and_pss_padding() {
    let config = SigningTestConfig::new(SigningAlgorithm::PS256);
    let app = AppState::initialize(&config.path).unwrap().router();
    let (status, discovery) = get_json(app.clone(), "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["PS256"])
    );
    let (status, jwks) = get_json(app.clone(), "/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "PS256");
    assert_eq!(key["use"], "sig");
    for absent in ["crv", "x", "y", "d", "p", "q"] {
        assert!(key.get(absent).is_none(), "unexpected key field {absent}");
    }
    let (status, response) = post_token_form(
        app,
        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = response["access_token"].as_str().unwrap();
    assert_eq!(decode_header(token).unwrap().alg, Algorithm::PS256);
    let claims = verify_jwt_with_jwks(token, &jwks);
    assert_eq!(claims["sub"], "svc-a");
    assert_eq!(claims["scope"], "default");

    // Verify with RustCrypto as well as jsonwebtoken/ring, enforcing the JOSE
    // PS256 parameters: SHA-256, MGF1-SHA256, and a 32-byte salt.
    let public_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(key["n"].as_str().unwrap()).unwrap()),
        rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(key["e"].as_str().unwrap()).unwrap()),
    )
    .unwrap();
    let (signing_input, signature) = token.rsplit_once('.').unwrap();
    public_key
        .verify(
            rsa::Pss::new_with_salt::<Sha256>(32),
            &Sha256::digest(signing_input.as_bytes()),
            &URL_SAFE_NO_PAD.decode(signature).unwrap(),
        )
        .expect("token must use PS256 padding and salt length");
}

#[test]
fn ps256_rejects_rsa_keys_shorter_than_2048_bits_at_startup() {
    let config = SigningTestConfig::new(SigningAlgorithm::PS256);
    fs::copy(
        fixture_config_dir("keys").join("rsa1024.pem"),
        config.path.join("keys/signing-key.pem"),
    )
    .unwrap();
    let error = AppState::initialize(&config.path)
        .err()
        .expect("weak test key must fail startup");
    assert!(error.to_string().contains("at least 2048 bits"), "{error}");
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
        (
            SigningAlgorithm::PS256,
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
    for algorithm in ["HS256", "ES384", "PS384", "none"] {
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
