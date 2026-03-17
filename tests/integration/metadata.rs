use axum::http::StatusCode;

use crate::common::{get_json, test_app};

#[tokio::test]
async fn serves_openid_configuration() {
    let app = test_app("config-basic");
    let (status, body) = get_json(app, "/.well-known/openid-configuration").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["issuer"], "https://pocket-oid.local");
    assert_eq!(
        body["token_endpoint"],
        "https://pocket-oid.local/oauth/token"
    );
    assert_eq!(body["jwks_uri"], "https://pocket-oid.local/jwks.json");
}

#[tokio::test]
async fn serves_jwks_with_required_fields() {
    let app = test_app("config-basic");
    let (status, body) = get_json(app, "/jwks.json").await;

    assert_eq!(status, StatusCode::OK);
    let first_key = &body["keys"][0];
    assert!(first_key["kid"].as_str().is_some());
    assert_eq!(first_key["kty"], "RSA");
    assert_eq!(first_key["alg"], "RS256");
    assert!(first_key["n"].as_str().is_some());
    assert!(first_key["e"].as_str().is_some());
}
