use std::{
    fs,
    path::{Path, PathBuf},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use pocket_oid::app::AppState;
use pocket_oid::config::SigningAlgorithm;
use serde_json::Value;
use tower::ServiceExt;

pub fn fixture_config_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

pub fn test_app(name: &str) -> Router {
    let state =
        AppState::initialize(&fixture_config_dir(name)).expect("app state should initialize");
    state.router()
}

pub async fn post_token_form(app: Router, form: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should read");
    let json = serde_json::from_slice(&body).expect("response should be valid JSON");
    (status, json)
}

pub async fn get_json(app: Router, path: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::get(path)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should read");
    let json = serde_json::from_slice(&body).expect("response should be valid JSON");
    (status, json)
}

pub fn verify_jwt_with_jwks(token: &str, jwks: &Value) -> Value {
    verify_jwt_with_jwks_for(
        token,
        jwks,
        "https://pocket-oid.local",
        "https://api.example.local",
    )
}

pub fn verify_jwt_with_jwks_for(token: &str, jwks: &Value, issuer: &str, audience: &str) -> Value {
    let header = decode_header(token).expect("header should decode");
    let kid = header.kid.expect("kid should be present");

    let key = jwks["keys"]
        .as_array()
        .expect("keys should be array")
        .iter()
        .find(|entry| entry["kid"].as_str() == Some(kid.as_str()))
        .expect("matching key should exist");

    assert_eq!(key["alg"], serde_json::to_value(header.alg).unwrap());
    assert!(matches!(
        header.alg,
        Algorithm::RS256 | Algorithm::ES256 | Algorithm::PS256
    ));
    let jwk = serde_json::from_value(key.clone()).expect("JWK should parse");
    let decoding_key = DecodingKey::from_jwk(&jwk).expect("JWK should load");
    let mut validation = Validation::new(header.alg);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);

    decode::<Value>(token, &decoding_key, &validation)
        .expect("token should validate")
        .claims
}

pub async fn request(app: Router, request: Request<Body>) -> Response<Body> {
    app.oneshot(request).await.expect("request should succeed")
}

pub fn signing_key_path(algorithm: SigningAlgorithm) -> PathBuf {
    match algorithm {
        SigningAlgorithm::RS256 | SigningAlgorithm::PS256 => {
            fixture_config_dir("config-basic").join("keys/signing-key.pem")
        }
        SigningAlgorithm::ES256 => fixture_config_dir("keys").join("es256.pem"),
    }
}

pub fn configure_signing(config_dir: &Path, algorithm: SigningAlgorithm) {
    let provider_path = config_dir.join("provider.json");
    let mut provider: Value = serde_json::from_slice(&fs::read(&provider_path).unwrap()).unwrap();
    provider["signing_algorithm"] = serde_json::to_value(algorithm).unwrap();
    fs::write(provider_path, serde_json::to_vec_pretty(&provider).unwrap()).unwrap();
    fs::copy(
        signing_key_path(algorithm),
        config_dir.join("keys/signing-key.pem"),
    )
    .unwrap();
}

pub struct SigningTestConfig {
    pub path: PathBuf,
}

impl SigningTestConfig {
    pub fn new(algorithm: SigningAlgorithm) -> Self {
        let path =
            std::env::temp_dir().join(format!("pocket-oid-signing-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(path.join("keys")).unwrap();
        let config = Self { path };
        for file in [
            "provider.json",
            "clients.json",
            "users.json",
            "token_template.json",
        ] {
            fs::copy(
                fixture_config_dir("config-basic").join(file),
                config.path.join(file),
            )
            .unwrap();
        }
        configure_signing(&config.path, algorithm);
        config
    }
}

impl Drop for SigningTestConfig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
