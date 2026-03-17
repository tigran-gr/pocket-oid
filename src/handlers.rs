use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{
    app::{AppState, DiscoveryDocument},
    config::Client,
    crypto::JwkSet,
    error::ApiError,
    token::TokenContext,
};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub async fn token_endpoint(
    State(state): State<AppState>,
    axum::extract::Form(request): axum::extract::Form<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    if request.grant_type != "client_credentials" {
        return Err(ApiError::UnsupportedGrantType);
    }
    let client_id = request
        .client_id
        .ok_or_else(|| ApiError::invalid_request("client_id is required"))?;
    let client_secret = request
        .client_secret
        .ok_or_else(|| ApiError::invalid_request("client_secret is required"))?;

    let client = authenticate_client(&state, &client_id, &client_secret)?;
    let scope_text = validate_scopes(request.scope.as_deref(), client)?;

    let issued_at = chrono::Utc::now();
    let ttl = client
        .token_ttl_seconds
        .unwrap_or(state.provider.token_ttl_seconds);
    if ttl == 0 {
        return Err(ApiError::internal(anyhow::anyhow!(
            "invalid token ttl configuration"
        )));
    }
    let expires_at = issued_at
        .checked_add_signed(chrono::Duration::seconds(ttl as i64))
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("ttl overflow")))?;

    let context = TokenContext {
        client,
        scope: scope_text.as_deref(),
        issued_at,
        expires_at,
        audience: client.audience.as_deref(),
        uuid: uuid::Uuid::new_v4(),
    };

    let claims = state
        .token_template
        .render(&context)
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;

    let header = state.signing_key.header();
    let token = jsonwebtoken::encode(&header, &claims, &state.signing_key.encoding_key)
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;

    let response = TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: ttl,
        scope: scope_text,
    };

    tracing::info!(
        client_id = %client.client_id,
        scope = response.scope.as_deref().unwrap_or(""),
        expires_in = response.expires_in,
        "issued access token"
    );

    Ok(Json(response))
}

pub async fn openid_configuration(State(state): State<AppState>) -> Json<DiscoveryDocument> {
    Json(state.discovery.clone())
}

pub async fn jwks(State(state): State<AppState>) -> Json<JwkSet> {
    Json(state.jwk_set.clone())
}

pub async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if state.clients.is_empty() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}

fn authenticate_client<'a>(
    state: &'a AppState,
    client_id: &str,
    secret: &str,
) -> Result<&'a Client, ApiError> {
    let client = state
        .clients
        .get(client_id)
        .ok_or(ApiError::InvalidClient)?;
    if !constant_time_eq(&client.client_secret, secret) {
        return Err(ApiError::InvalidClient);
    }
    Ok(client)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn validate_scopes<'a>(
    requested: Option<&'a str>,
    client: &'a Client,
) -> Result<Option<String>, ApiError> {
    match requested {
        Some(scopes) => {
            let parsed: Vec<String> = scopes
                .split_whitespace()
                .filter(|scope| !scope.is_empty())
                .map(|scope| scope.to_string())
                .collect();
            if parsed.is_empty() {
                return Err(ApiError::invalid_scope("scope cannot be empty"));
            }
            for scope in &parsed {
                if !client.allowed_scopes.contains(scope) {
                    return Err(ApiError::invalid_scope(format!(
                        "requested scope '{scope}' is not permitted"
                    )));
                }
            }
            Ok(Some(parsed.join(" ")))
        }
        None => {
            if client.allowed_scopes.is_empty() {
                Ok(None)
            } else {
                let scopes: Vec<String> = client.allowed_scopes.iter().cloned().collect();
                let combined = scopes.join(" ");
                Ok(Some(combined))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::app::AppState;

    fn config_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config")
    }

    #[tokio::test]
    async fn fetches_access_token_with_client_credentials_flow() {
        let state = AppState::initialize(&config_dir()).expect("app state should initialize");
        let app = state.router();

        let response = app
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should read");
        let token_response: Value =
            serde_json::from_slice(&response_body).expect("token response should be valid JSON");

        assert_eq!(token_response["token_type"], "Bearer");
        assert_eq!(token_response["expires_in"], 3600);
        assert_eq!(token_response["scope"], "default");

        let access_token = token_response["access_token"]
            .as_str()
            .expect("access token should be present");
        let public_key = fs::read(config_dir().join("keys").join("signing-key.pub"))
            .expect("public key should be readable");
        let decoding_key =
            DecodingKey::from_rsa_pem(&public_key).expect("public key should parse");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&["https://pocket-oid.local"]);
        validation.set_audience(&["https://api.example.local"]);

        let token_data = decode::<Value>(access_token, &decoding_key, &validation)
            .expect("access token should verify");

        assert_eq!(token_data.claims["sub"], "svc-a");
        assert_eq!(token_data.claims["scope"], "default");
        assert_eq!(token_data.claims["custom"]["tenant"], "acme");
        assert_eq!(token_data.claims["custom"]["env"], "dev");
        assert!(token_data.claims["jti"].as_str().is_some());
    }

    #[tokio::test]
    async fn fetches_access_token_with_jwks_key_discovered_from_well_known_config() {
        let state = AppState::initialize(&config_dir()).expect("app state should initialize");
        let app = state.router();

        let token_response = app
            .clone()
            .oneshot(
                Request::post("/oauth/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(token_response.status(), StatusCode::OK);

        let token_body = to_bytes(token_response.into_body(), usize::MAX)
            .await
            .expect("response body should read");
        let token_json: Value =
            serde_json::from_slice(&token_body).expect("token response should be valid JSON");

        let well_known_response = app
            .clone()
            .oneshot(
                Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(well_known_response.status(), StatusCode::OK);

        let well_known_body = to_bytes(well_known_response.into_body(), usize::MAX)
            .await
            .expect("response body should read");
        let well_known_json: Value = serde_json::from_slice(&well_known_body)
            .expect("well-known response should be valid JSON");
        let jwks_uri = well_known_json["jwks_uri"]
            .as_str()
            .expect("jwks_uri should be present");
        let jwks_path = jwks_uri
            .strip_prefix("https://pocket-oid.local")
            .expect("jwks_uri should use configured issuer");

        let jwks_response = app
            .oneshot(
                Request::get(jwks_path)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(jwks_response.status(), StatusCode::OK);

        let jwks_body = to_bytes(jwks_response.into_body(), usize::MAX)
            .await
            .expect("response body should read");
        let jwks_json: Value =
            serde_json::from_slice(&jwks_body).expect("jwks response should be valid JSON");

        let access_token = token_json["access_token"]
            .as_str()
            .expect("access token should be present");
        let token_header = decode_header(access_token).expect("token header should decode");
        let kid = token_header.kid.expect("token header should contain key id");

        let jwk = jwks_json["keys"]
            .as_array()
            .expect("jwks keys should be an array")
            .iter()
            .find(|entry| entry["kid"].as_str() == Some(kid.as_str()))
            .expect("jwks should include the signing key");
        let modulus = jwk["n"].as_str().expect("jwk should include modulus");
        let exponent = jwk["e"].as_str().expect("jwk should include exponent");

        let decoding_key = DecodingKey::from_rsa_components(modulus, exponent)
            .expect("jwk components should parse");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&["https://pocket-oid.local"]);
        validation.set_audience(&["https://api.example.local"]);

        let token_data = decode::<Value>(access_token, &decoding_key, &validation)
            .expect("access token should verify");

        assert_eq!(token_data.claims["sub"], "svc-a");
        assert_eq!(token_data.claims["scope"], "default");
    }

    #[tokio::test]
    async fn fetches_access_tokens_for_parallel_client_credentials_requests() {
        let state = AppState::initialize(&config_dir()).expect("app state should initialize");
        let app = state.router();

        let request = || {
            Request::post("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=client_credentials&client_id=svc-a&client_secret=supersecret",
                ))
                .expect("request should build")
        };

        let (first_response, second_response) = tokio::join!(
            app.clone().oneshot(request()),
            app.clone().oneshot(request())
        );

        for response in [first_response, second_response] {
            let response = response.expect("request should succeed");
            assert_eq!(response.status(), StatusCode::OK);

            let response_body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("response body should read");
            let token_response: Value =
                serde_json::from_slice(&response_body).expect("token response should be valid JSON");

            assert_eq!(token_response["token_type"], "Bearer");
            assert_eq!(token_response["expires_in"], 3600);
            assert_eq!(token_response["scope"], "default");
            assert!(token_response["access_token"].as_str().is_some());
        }
    }
}
