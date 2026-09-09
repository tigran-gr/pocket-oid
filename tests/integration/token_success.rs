use std::fs;

use axum::http::StatusCode;
use pocket_oid::{app::AppState, config::SigningAlgorithm};
use serde_json::{Value, json};

use crate::common::{SigningTestConfig, get_json, post_token_form, test_app, verify_jwt_with_jwks};

#[tokio::test]
async fn issues_access_token_and_verifies_with_jwks() {
    let app = test_app("config-basic");

    let (token_status, token_body) = post_token_form(
        app.clone(),
        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
    )
    .await;

    assert_eq!(token_status, StatusCode::OK);
    assert_eq!(token_body["token_type"], "Bearer");
    assert_eq!(token_body["expires_in"], 3600);
    assert_eq!(token_body["scope"], "default");

    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token should be present");

    let (jwks_status, jwks_body) = get_json(app.clone(), "/jwks.json").await;
    assert_eq!(jwks_status, StatusCode::OK);

    let claims = verify_jwt_with_jwks(access_token, &jwks_body);

    assert_eq!(claims["sub"], "svc-a");
    assert_eq!(claims["scope"], "default");
    assert_eq!(claims["custom"]["tenant"], "acme");
    assert_eq!(claims["custom"]["env"], "dev");
    assert!(claims["jti"].as_str().is_some());
}

#[tokio::test]
async fn client_specific_ttl_sets_token_expiration() {
    const CLIENT_TTL_SECONDS: i64 = 900;

    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    let clients_path = config.path.join("clients.json");
    let mut clients: Value = serde_json::from_slice(&fs::read(&clients_path).unwrap()).unwrap();
    clients[0]["token_ttl_seconds"] = json!(CLIENT_TTL_SECONDS);
    fs::write(clients_path, serde_json::to_vec_pretty(&clients).unwrap()).unwrap();
    let app = AppState::initialize(&config.path)
        .expect("app state should initialize")
        .router();

    let (token_status, token_body) = post_token_form(
        app.clone(),
        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
    )
    .await;

    assert_eq!(token_status, StatusCode::OK);
    assert_eq!(token_body["expires_in"], CLIENT_TTL_SECONDS);

    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token should be present");
    let (jwks_status, jwks_body) = get_json(app, "/jwks.json").await;
    assert_eq!(jwks_status, StatusCode::OK);
    let claims = verify_jwt_with_jwks(access_token, &jwks_body);
    let issued_at = claims["iat"].as_i64().expect("iat should be numeric");
    let expires_at = claims["exp"].as_i64().expect("exp should be numeric");

    assert_eq!(expires_at - issued_at, CLIENT_TTL_SECONDS);
}

#[tokio::test]
async fn supports_parallel_token_requests() {
    let app = test_app("config-basic");

    let request = || {
        post_token_form(
            app.clone(),
            "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
        )
    };

    let (first, second) = tokio::join!(request(), request());

    for (status, body) in [first, second] {
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["token_type"], "Bearer");
        assert!(body["access_token"].as_str().is_some());
    }
}
