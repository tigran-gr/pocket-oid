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
