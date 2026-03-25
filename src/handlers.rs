use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    app::{AppState, DiscoveryDocument},
    auth::NewAuthorizationCode,
    config::Client,
    crypto::JwkSet,
    error::ApiError,
    frontend,
    token::TokenContext,
};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub return_to: String,
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub decision: String,
    pub return_to: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<AuthorizeRequest>,
) -> Response {
    let client = match state.clients.get(&request.client_id) {
        Some(client) => client,
        None => {
            return authorization_error_redirect(
                &request.redirect_uri,
                "unauthorized_client",
                request.state,
            );
        }
    };
    if request.response_type != "code" || !client.response_types.contains("code") {
        return authorization_error_redirect(
            &request.redirect_uri,
            "unsupported_response_type",
            request.state,
        );
    }
    if !client.redirect_uris.contains(&request.redirect_uri) {
        return authorization_error_redirect(
            &request.redirect_uri,
            "invalid_request",
            request.state,
        );
    }
    let scope = match validate_scopes(request.scope.as_deref(), client) {
        Ok(scope) => scope,
        Err(_) => {
            return authorization_error_redirect(
                &request.redirect_uri,
                "invalid_scope",
                request.state,
            );
        }
    };

    let session = extract_session_id(&headers)
        .and_then(|session_id| state.auth_store.get_session(&session_id));

    let return_to = build_authorize_return(&request);
    if let Some(session) = session {
        let html = frontend::consent_page(
            &return_to,
            &request.client_id,
            &scope.unwrap_or_default(),
            &session.username,
        );
        return Html(html).into_response();
    }

    let html = frontend::login_page(&return_to, None);
    Html(html).into_response()
}

pub async fn login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let Some(user) = state.users.get(&form.username) else {
        return Html(frontend::login_page(
            &form.return_to,
            Some("Invalid credentials"),
        ))
        .into_response();
    };
    if !constant_time_eq(&user.password, &form.password) {
        return Html(frontend::login_page(
            &form.return_to,
            Some("Invalid credentials"),
        ))
        .into_response();
    }
    let Some(session) =
        state
            .auth_store
            .create_session(user.id.clone(), user.username.clone(), 3600)
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let mut response = Redirect::to(&form.return_to).into_response();
    let cookie = format!(
        "session_id={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600",
        session.session_id
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

pub async fn consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    let Some(session_id) = extract_session_id(&headers) else {
        return Redirect::to("/authorize").into_response();
    };
    let Some(session) = state.auth_store.get_session(&session_id) else {
        return Redirect::to("/authorize").into_response();
    };

    let request = parse_authorize_return(&form.return_to);

    if form.decision != "approve" {
        return authorization_error_redirect(&request.redirect_uri, "access_denied", request.state);
    }

    let Some(code) = state.auth_store.issue_authorization_code(
        NewAuthorizationCode {
            client_id: request.client_id,
            user_id: session.user_id,
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope,
            nonce: request.nonce,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
        },
        120,
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let mut params = vec![format!("code={}", encode_uri_component(&code))];
    if let Some(state_value) = request.state.as_deref() {
        params.push(format!("state={}", encode_uri_component(state_value)));
    }
    let redirect = format!("{}?{}", request.redirect_uri, params.join("&"));
    Redirect::to(&redirect).into_response()
}

pub async fn token_endpoint(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let client_id = request
        .client_id
        .ok_or_else(|| ApiError::invalid_request("client_id is required"))?;
    let client_secret = request
        .client_secret
        .ok_or_else(|| ApiError::invalid_request("client_secret is required"))?;

    let client = authenticate_client(&state, &client_id, &client_secret)?;

    match request.grant_type.as_str() {
        "client_credentials" => {
            let scope_text = validate_scopes(request.scope.as_deref(), client)?;
            issue_token(&state, client, scope_text, client.client_id.clone())
        }
        "authorization_code" => {
            let code = request
                .code
                .ok_or_else(|| ApiError::invalid_request("code is required"))?;
            let redirect_uri = request
                .redirect_uri
                .ok_or_else(|| ApiError::invalid_request("redirect_uri is required"))?;
            let record = state
                .auth_store
                .consume_authorization_code(&code)
                .ok_or_else(|| {
                    ApiError::invalid_grant("authorization code is invalid or expired")
                })?;
            if record.client_id != client.client_id {
                return Err(ApiError::invalid_grant(
                    "authorization code client mismatch",
                ));
            }
            if record.redirect_uri != redirect_uri {
                return Err(ApiError::invalid_grant("redirect_uri mismatch"));
            }
            verify_pkce(
                client,
                &record.code_challenge,
                &record.code_challenge_method,
                request.code_verifier.as_deref(),
            )?;
            issue_token(&state, client, record.scope, record.user_id)
        }
        _ => Err(ApiError::UnsupportedGrantType),
    }
}

fn issue_token(
    state: &AppState,
    client: &Client,
    scope_text: Option<String>,
    subject: String,
) -> Result<Json<TokenResponse>, ApiError> {
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
        subject: &subject,
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

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: ttl,
        scope: scope_text,
    }))
}

fn verify_pkce(
    client: &Client,
    code_challenge: &Option<String>,
    code_challenge_method: &Option<String>,
    code_verifier: Option<&str>,
) -> Result<(), ApiError> {
    if code_challenge.is_none() {
        if client.require_pkce {
            return Err(ApiError::invalid_grant("pkce is required for this client"));
        }
        return Ok(());
    }

    let verifier =
        code_verifier.ok_or_else(|| ApiError::invalid_request("code_verifier is required"))?;
    let expected = code_challenge
        .as_ref()
        .expect("code_challenge presence checked");
    let method = code_challenge_method.as_deref().unwrap_or("plain");

    let computed = match method {
        "plain" => verifier.to_string(),
        "S256" => {
            let hash = Sha256::digest(verifier.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
        }
        _ => return Err(ApiError::invalid_grant("unsupported code_challenge_method")),
    };

    if !constant_time_eq(expected, &computed) {
        return Err(ApiError::invalid_grant("pkce verification failed"));
    }

    Ok(())
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

fn validate_scopes(requested: Option<&str>, client: &Client) -> Result<Option<String>, ApiError> {
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
                Ok(Some(
                    client
                        .allowed_scopes
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" "),
                ))
            }
        }
    }
}

fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies
        .split(';')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let (key, value) = trimmed.split_once('=')?;
            Some((key.trim(), value.trim()))
        })
        .find_map(|(key, value)| (key == "session_id").then(|| value.to_string()))
}

fn build_authorize_return(request: &AuthorizeRequest) -> String {
    let mut params = vec![
        format!(
            "response_type={}",
            encode_uri_component(&request.response_type)
        ),
        format!("client_id={}", encode_uri_component(&request.client_id)),
        format!(
            "redirect_uri={}",
            encode_uri_component(&request.redirect_uri)
        ),
    ];
    if let Some(scope) = request.scope.as_deref() {
        params.push(format!("scope={}", encode_uri_component(scope)));
    }
    if let Some(state) = request.state.as_deref() {
        params.push(format!("state={}", encode_uri_component(state)));
    }
    if let Some(nonce) = request.nonce.as_deref() {
        params.push(format!("nonce={}", encode_uri_component(nonce)));
    }
    if let Some(code_challenge) = request.code_challenge.as_deref() {
        params.push(format!(
            "code_challenge={}",
            encode_uri_component(code_challenge)
        ));
    }
    if let Some(code_challenge_method) = request.code_challenge_method.as_deref() {
        params.push(format!(
            "code_challenge_method={}",
            encode_uri_component(code_challenge_method)
        ));
    }
    format!("/authorize?{}", params.join("&"))
}

fn parse_authorize_return(return_to: &str) -> AuthorizeRequest {
    let query = return_to
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default();
    let mut request = AuthorizeRequest {
        response_type: String::new(),
        client_id: String::new(),
        redirect_uri: String::new(),
        scope: None,
        state: None,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
    };
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = decode_uri_component(value);
        match key {
            "response_type" => request.response_type = value,
            "client_id" => request.client_id = value,
            "redirect_uri" => request.redirect_uri = value,
            "scope" => request.scope = Some(value),
            "state" => request.state = Some(value),
            "nonce" => request.nonce = Some(value),
            "code_challenge" => request.code_challenge = Some(value),
            "code_challenge_method" => request.code_challenge_method = Some(value),
            _ => {}
        }
    }
    request
}

fn authorization_error_redirect(
    redirect_uri: &str,
    error: &str,
    state: Option<String>,
) -> Response {
    let mut params = vec![format!("error={}", encode_uri_component(error))];
    if let Some(state_value) = state.as_deref() {
        params.push(format!("state={}", encode_uri_component(state_value)));
    }
    Redirect::to(&format!("{}?{}", redirect_uri, params.join("&"))).into_response()
}

fn encode_uri_component(value: &str) -> String {
    value.replace(' ', "%20")
}

fn decode_uri_component(value: &str) -> String {
    value.replace("%20", " ")
}
