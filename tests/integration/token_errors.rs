use std::fs;

use axum::http::StatusCode;
use pocket_oid::{
    app::AppState,
    auth::{AuthContext, NewAuthorizationCode},
    config::SigningAlgorithm,
};
use serde_json::Value;

use crate::common::{SigningTestConfig, fixture_config_dir, post_token_form, test_app};

#[tokio::test]
async fn rejects_unsupported_grant_type() {
    let app = test_app("config-basic");
    let (status, body) = post_token_form(
        app,
        "grant_type=password&client_id=svc-a&client_secret=supersecret",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn rejects_invalid_client_credentials() {
    let app = test_app("config-basic");
    let (status, body) = post_token_form(
        app,
        "grant_type=client_credentials&client_id=svc-a&client_secret=wrong",
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn rejects_invalid_scope() {
    let app = test_app("config-basic");
    let (status, body) = post_token_form(
        app,
        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret&scope=admin",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn rejects_missing_required_form_fields() {
    let app = test_app("config-basic");
    let (status, body) = post_token_form(app, "grant_type=client_credentials").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn rejects_replayed_authorization_code() {
    let state = AppState::initialize(&fixture_config_dir("config-basic")).unwrap();
    let code = issue_authorization_code(&state, "svc-a", 60);

    let (status, body) = exchange_authorization_code(&state, &code, "svc-a", "supersecret").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());

    let (status, body) = exchange_authorization_code(&state, &code, "svc-a", "supersecret").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn rejects_expired_authorization_code() {
    let state = AppState::initialize(&fixture_config_dir("config-basic")).unwrap();
    let valid_code = issue_authorization_code(&state, "svc-a", 60);
    // A negative TTL makes the code expired immediately, without timing-dependent sleeps.
    let expired_code = issue_authorization_code(&state, "svc-a", -1);

    let (status, body) =
        exchange_authorization_code(&state, &expired_code, "svc-a", "supersecret").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    let (status, body) =
        exchange_authorization_code(&state, &valid_code, "svc-a", "supersecret").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn rejects_authorization_code_from_another_client() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    let clients_path = config.path.join("clients.json");
    let mut clients: Vec<Value> =
        serde_json::from_slice(&fs::read(&clients_path).unwrap()).unwrap();
    let mut second_client = clients[0].clone();
    second_client["client_id"] = "svc-b".into();
    second_client["client_secret"] = "second-client-secret".into();
    // Share redirect URI and scopes so only the client binding can reject the exchange.
    clients.push(second_client);
    fs::write(clients_path, serde_json::to_vec(&clients).unwrap()).unwrap();
    let state = AppState::initialize(&config.path).unwrap();

    let own_code = issue_authorization_code(&state, "svc-b", 60);
    let (status, body) =
        exchange_authorization_code(&state, &own_code, "svc-b", "second-client-secret").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());

    let other_client_code = issue_authorization_code(&state, "svc-b", 60);
    let (status, body) =
        exchange_authorization_code(&state, &other_client_code, "svc-a", "supersecret").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn rejects_authorization_code_with_different_registered_redirect_uri() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    let clients_path = config.path.join("clients.json");
    let mut clients: Vec<Value> =
        serde_json::from_slice(&fs::read(&clients_path).unwrap()).unwrap();
    let alternate_redirect = "https://app.example.local/alternate";
    // Both URIs are registered, so only the code's original redirect binding can reject it.
    clients[0]["redirect_uris"]
        .as_array_mut()
        .unwrap()
        .push(alternate_redirect.into());
    fs::write(clients_path, serde_json::to_vec(&clients).unwrap()).unwrap();
    let state = AppState::initialize(&config.path).unwrap();

    let valid_code = issue_authorization_code(&state, "svc-a", 60);
    let (status, body) =
        exchange_authorization_code(&state, &valid_code, "svc-a", "supersecret").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());

    // Use a fresh code so replay protection cannot hide a missing redirect check.
    let code = issue_authorization_code(&state, "svc-a", 60);
    let (status, body) = exchange_authorization_code_at_redirect(
        &state,
        &code,
        "svc-a",
        "supersecret",
        alternate_redirect,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
}

fn issue_authorization_code(state: &AppState, client_id: &str, ttl_seconds: i64) -> String {
    state
        .auth_store
        .issue_authorization_code(
            NewAuthorizationCode {
                client_id: client_id.to_string(),
                user_id: "user-alice".to_string(),
                redirect_uri: "https://app.example.local/callback".to_string(),
                scope: Some("default".to_string()),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                auth_context: AuthContext::Local,
            },
            ttl_seconds,
        )
        .expect("authorization code should be issued")
}

async fn exchange_authorization_code(
    state: &AppState,
    code: &str,
    client_id: &str,
    client_secret: &str,
) -> (StatusCode, Value) {
    exchange_authorization_code_at_redirect(
        state,
        code,
        client_id,
        client_secret,
        "https://app.example.local/callback",
    )
    .await
}

async fn exchange_authorization_code_at_redirect(
    state: &AppState,
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> (StatusCode, Value) {
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("code", code),
        ])
        .finish();
    post_token_form(state.router(), &form).await
}
