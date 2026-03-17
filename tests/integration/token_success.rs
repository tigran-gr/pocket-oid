use axum::http::StatusCode;

use crate::common::{get_json, post_token_form, test_app, verify_jwt_with_jwks};

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
