use std::path::PathBuf;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use pocket_oid::app::AppState;
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

    let modulus = key["n"].as_str().expect("modulus should be present");
    let exponent = key["e"].as_str().expect("exponent should be present");

    let decoding_key =
        DecodingKey::from_rsa_components(modulus, exponent).expect("jwk should parse");
    let mut validation = Validation::new(Algorithm::RS256);
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
