use axum::http::StatusCode;

use crate::common::{post_token_form, test_app};

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
