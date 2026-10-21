use std::fs;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use pocket_oid::{
    app::AppState,
    auth::{AuthContext, NewAuthorizationCode},
    config::SigningAlgorithm,
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use url::Url;

use crate::common::{
    SigningTestConfig, get_json, post_token_form, request, verify_jwt_with_jwks_for,
};

fn email_config(sqlite: bool, email: Option<&str>, verified: bool) -> SigningTestConfig {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    let path = config.path.join("clients.json");
    let mut clients: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    clients[0]["scopes"] = json!(["default", "openid", "email", "emailish"]);
    clients[0]["consent_mode"] = json!("skip");
    fs::write(path, serde_json::to_vec(&clients).unwrap()).unwrap();

    let path = config.path.join("users.json");
    let mut users: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    if sqlite {
        let connection = Connection::open(config.path.join("users.sqlite3")).unwrap();
        // Start from the deployed v1 schema and exercise migration during startup.
        connection
            .execute_batch(
                "CREATE TABLE users (
                id TEXT PRIMARY KEY NOT NULL, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             ); PRAGMA user_version = 1;",
            )
            .unwrap();
        connection.execute(
            "INSERT INTO users (id, username, password_hash) VALUES ('user-alice', 'alice', ?1)",
            params![users["users"][0]["password_hash"].as_str().unwrap()],
        ).unwrap();
        users = json!({"provider": "sqlite", "path": "users.sqlite3"});
    } else if let Some(email) = email {
        users["users"][0]["email"] = json!(email);
        users["users"][0]["email_verified"] = json!(verified);
    }
    fs::write(path, serde_json::to_vec(&users).unwrap()).unwrap();
    config
}

fn form(fields: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish()
}

async fn exchange(state: &AppState, code: &str) -> Value {
    let (status, token) = post_token_form(
        state.router(),
        &form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "svc-a"),
            ("client_secret", "supersecret"),
            ("code", code),
            ("redirect_uri", "https://app.example.local/callback"),
            // Token requests must not expand the code's previously authorized scopes.
            ("scope", "openid email"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{token}");
    token
}

async fn verify_tokens(state: &AppState, token: &Value) -> Value {
    let (_, jwks) = get_json(state.router(), "/jwks.json").await;
    let access = verify_jwt_with_jwks_for(
        token["access_token"].as_str().unwrap(),
        &jwks,
        "https://pocket-oid.local",
        "https://api.example.local",
    );
    assert!(access.get("email").is_none());
    assert!(access.get("email_verified").is_none());
    verify_jwt_with_jwks_for(
        token["id_token"].as_str().unwrap(),
        &jwks,
        "https://pocket-oid.local",
        "svc-a",
    )
}

#[tokio::test]
async fn local_code_flow_issues_stored_email_and_boolean_verification_for_both_backends() {
    for sqlite in [false, true] {
        for (email, verified) in [
            (Some("alice@example.test"), true),
            (Some("alice@example.test"), false),
            (None, false),
        ] {
            let config = email_config(sqlite, email, verified);
            let state = AppState::initialize(&config.path).unwrap();
            let authorize = format!(
                "/authorize?{}",
                form(&[
                    ("response_type", "code"),
                    ("client_id", "svc-a"),
                    ("redirect_uri", "https://app.example.local/callback"),
                    ("scope", "openid email"),
                    ("nonce", "email-nonce"),
                ])
            );
            let login = request(
                state.router(),
                Request::post("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form(&[
                        ("username", "alice"),
                        ("password", "password123"),
                        ("return_to", &authorize),
                    ])))
                    .unwrap(),
            )
            .await;
            assert_eq!(login.status(), StatusCode::SEE_OTHER);
            let cookie = login.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let response = request(
                state.router(),
                Request::get(&authorize)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let location =
                Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
            let code = location
                .query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned();
            if sqlite {
                // Update after login/code issuance: token exchange must use current stored status.
                let connection = Connection::open(config.path.join("users.sqlite3")).unwrap();
                connection
                    .execute(
                        "UPDATE users SET email = ?1, email_verified = ?2 WHERE id = 'user-alice'",
                        params![email, verified],
                    )
                    .unwrap();
            }
            let token = exchange(&state, &code).await;
            let claims = verify_tokens(&state, &token).await;
            assert_eq!(claims["sub"], "user-alice");
            assert_eq!(claims["nonce"], "email-nonce");
            if let Some(email) = email {
                assert_eq!(claims["email"], email);
                assert_eq!(claims["email_verified"], json!(verified));
            } else {
                assert!(claims.get("email").is_none());
                assert!(claims.get("email_verified").is_none());
            }
            let (replay, _) = post_token_form(
                state.router(),
                &form(&[
                    ("grant_type", "authorization_code"),
                    ("client_id", "svc-a"),
                    ("client_secret", "supersecret"),
                    ("code", &code),
                    ("redirect_uri", "https://app.example.local/callback"),
                ]),
            )
            .await;
            assert_eq!(replay, StatusCode::BAD_REQUEST);
        }
    }
}

#[tokio::test]
async fn email_scope_does_not_leak_to_core_clients_reauth_or_client_credentials() {
    let config = email_config(false, Some("alice@example.test"), true);
    let state = AppState::initialize(&config.path).unwrap();
    for (scope, auth_context) in [
        ("openid", AuthContext::Local),
        ("openid emailish", AuthContext::Local),
        // Even a colliding upstream subject must not resolve a local user's email.
        (
            "openid email",
            AuthContext::ReAuth {
                provider_id: "partner".into(),
                upstream_issuer: "https://partner.test".into(),
            },
        ),
    ] {
        let code = state
            .auth_store
            .issue_authorization_code(
                NewAuthorizationCode {
                    client_id: "svc-a".into(),
                    user_id: "user-alice".into(),
                    redirect_uri: "https://app.example.local/callback".into(),
                    scope: Some(scope.into()),
                    nonce: None,
                    code_challenge: None,
                    code_challenge_method: None,
                    auth_context,
                },
                120,
            )
            .unwrap();
        let token = exchange(&state, &code).await;
        assert_eq!(token["scope"], scope);
        let claims = verify_tokens(&state, &token).await;
        assert!(claims.get("email").is_none());
        assert!(claims.get("email_verified").is_none());
    }
    let (status, token) = post_token_form(
        state.router(),
        &form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-a"),
            ("client_secret", "supersecret"),
            ("scope", "openid email"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(token.get("id_token").is_none());
    let (_, jwks) = get_json(state.router(), "/jwks.json").await;
    let claims = verify_jwt_with_jwks_for(
        token["access_token"].as_str().unwrap(),
        &jwks,
        "https://pocket-oid.local",
        "https://api.example.local",
    );
    assert!(claims.get("email").is_none());
    assert!(claims.get("email_verified").is_none());
}

#[tokio::test]
async fn discovery_advertises_claims_and_email_scope_is_explicitly_opt_in() {
    let config = email_config(false, Some("alice@example.test"), true);
    let state = AppState::initialize(&config.path).unwrap();
    let (_, discovery) = get_json(state.router(), "/.well-known/openid-configuration").await;
    for claim in ["email", "email_verified"] {
        assert!(
            discovery["claims_supported"]
                .as_array()
                .unwrap()
                .contains(&json!(claim))
        );
    }
    assert!(
        discovery["scopes_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("email"))
    );
    let (status, token) = post_token_form(
        state.router(),
        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !token["scope"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .any(|s| s == "email")
    );
}
