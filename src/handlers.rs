use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::{
    app::{AppState, DiscoveryDocument},
    auth::{
        AuthContext, ConsumePendingReauth, DownstreamAuthorizationRequest, NewAuthorizationCode,
        NewPendingReauthConsent, NewPendingReauthTransaction,
    },
    config::{Client, ClientAuthMode, ConsentMode},
    crypto::JwkSet,
    error::ApiError,
    frontend,
    token::TokenContext,
    upstream::UpstreamAuthorizationRequest,
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
    pub prompt: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct ReauthCallbackRequest {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReauthConsentForm {
    pub decision: String,
    pub transaction_id: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<AuthorizeRequest>,
) -> Response {
    let (client, scope) = match validate_authorize_request(&state, &request) {
        Ok(validated) => validated,
        Err(response) => return *response,
    };

    if client.auth_mode == ClientAuthMode::ReAuth {
        return begin_reauth(&state, request, client, scope).await;
    }

    let session = extract_session_id(&headers)
        .and_then(|session_id| state.auth_store.get_session(&session_id));

    let return_to = build_authorize_return(&request);
    if let Some(session) =
        session.filter(|_| !requests_fresh_authentication(request.prompt.as_deref()))
    {
        return match client.consent_mode {
            ConsentMode::Always => {
                let html = frontend::consent_page(
                    &return_to,
                    &request.client_id,
                    &scope.unwrap_or_default(),
                    &session.username,
                );
                Html(html).into_response()
            }
            ConsentMode::Skip => issue_authorization_code_redirect(
                &state,
                request,
                session.user_id,
                scope,
                AuthContext::Local,
            ),
        };
    }

    let html = frontend::login_page(
        &state.provider.name,
        &return_to,
        None,
        state.provider.login_background_color.as_deref(),
    );
    Html(html).into_response()
}

pub async fn login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let Some(user) = state.users.get(&form.username) else {
        return Html(frontend::login_page(
            &state.provider.name,
            &form.return_to,
            Some("Invalid credentials"),
            state.provider.login_background_color.as_deref(),
        ))
        .into_response();
    };
    if !user.verify_password(&form.password) {
        return Html(frontend::login_page(
            &state.provider.name,
            &form.return_to,
            Some("Invalid credentials"),
            state.provider.login_background_color.as_deref(),
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
    let (_, scope) = match validate_authorize_request(&state, &request) {
        Ok(validated) => validated,
        Err(response) => return *response,
    };

    if form.decision != "approve" {
        return authorization_error_redirect(&request.redirect_uri, "access_denied", request.state);
    }

    issue_authorization_code_redirect(&state, request, session.user_id, scope, AuthContext::Local)
}

fn issue_authorization_code_redirect(
    state: &AppState,
    request: AuthorizeRequest,
    user_id: String,
    scope: Option<String>,
    auth_context: AuthContext,
) -> Response {
    let downstream = DownstreamAuthorizationRequest {
        client_id: request.client_id,
        redirect_uri: request.redirect_uri,
        scope,
        state: request.state,
        nonce: request.nonce,
        code_challenge: request.code_challenge,
        code_challenge_method: request.code_challenge_method,
    };
    issue_authorization_code_redirect_for_downstream(state, downstream, user_id, auth_context)
}

fn issue_authorization_code_redirect_for_downstream(
    state: &AppState,
    downstream: DownstreamAuthorizationRequest,
    user_id: String,
    auth_context: AuthContext,
) -> Response {
    let Some(code) = state.auth_store.issue_authorization_code(
        NewAuthorizationCode {
            client_id: downstream.client_id,
            user_id,
            redirect_uri: downstream.redirect_uri.clone(),
            scope: downstream.scope,
            nonce: downstream.nonce,
            code_challenge: downstream.code_challenge,
            code_challenge_method: downstream.code_challenge_method,
            auth_context,
        },
        120,
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let mut params = vec![format!("code={}", encode_uri_component(&code))];
    if let Some(state_value) = downstream.state.as_deref() {
        params.push(format!("state={}", encode_uri_component(state_value)));
    }
    let redirect = format!("{}?{}", downstream.redirect_uri, params.join("&"));
    Redirect::to(&redirect).into_response()
}

async fn begin_reauth(
    state: &AppState,
    request: AuthorizeRequest,
    client: &Client,
    scope: Option<String>,
) -> Response {
    let Some(re_auth) = client.re_auth.as_ref() else {
        return authorization_error_redirect(
            &request.redirect_uri,
            "server_error",
            request.state.clone(),
        );
    };
    let Some(provider) = state.trusted_providers.get(&re_auth.provider_id) else {
        return authorization_error_redirect(
            &request.redirect_uri,
            "server_error",
            request.state.clone(),
        );
    };
    let metadata = match state.upstream_client.discover(provider).await {
        Ok(metadata) => metadata,
        Err(error) => {
            warn!(provider_id = %provider.provider_id, error = ?error, "upstream OIDC discovery failed");
            return authorization_error_redirect(
                &request.redirect_uri,
                "temporarily_unavailable",
                request.state.clone(),
            );
        }
    };

    let upstream_state = random_url_safe_token();
    let upstream_nonce = random_url_safe_token();
    let pkce_verifier = provider.require_pkce.then(random_url_safe_token);
    let authorization_url = match state.upstream_client.build_authorization_url(
        UpstreamAuthorizationRequest {
            provider,
            metadata: &metadata,
            upstream_scopes: &re_auth.upstream_scopes,
            state: &upstream_state,
            nonce: &upstream_nonce,
            pkce_verifier: pkce_verifier.as_deref(),
            prompt_login: requests_fresh_authentication(request.prompt.as_deref()),
        },
    ) {
        Ok(url) => url,
        Err(error) => {
            warn!(provider_id = %provider.provider_id, error = ?error, "failed to build upstream authorization URL");
            return authorization_error_redirect(
                &request.redirect_uri,
                "server_error",
                request.state.clone(),
            );
        }
    };

    let downstream_redirect_uri = request.redirect_uri.clone();
    let downstream_state = request.state.clone();
    let downstream = DownstreamAuthorizationRequest {
        client_id: request.client_id,
        redirect_uri: request.redirect_uri.clone(),
        scope,
        state: request.state,
        nonce: request.nonce,
        code_challenge: request.code_challenge,
        code_challenge_method: request.code_challenge_method,
    };
    if state
        .auth_store
        .create_pending_reauth(
            NewPendingReauthTransaction {
                downstream,
                provider_id: provider.provider_id.clone(),
                upstream_state,
                upstream_nonce,
                pkce_verifier,
                provider_metadata: metadata,
            },
            300,
        )
        .is_none()
    {
        return authorization_error_redirect(
            &downstream_redirect_uri,
            "server_error",
            downstream_state,
        );
    }

    Redirect::to(&authorization_url).into_response()
}

pub async fn reauth_callback(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Query(callback): Query<ReauthCallbackRequest>,
) -> Response {
    if !state.trusted_providers.contains_key(&provider_id) {
        return authorization_error_response("invalid_request", Some("unknown re-auth provider"));
    }
    let Some(upstream_state) = callback.state.as_deref() else {
        return authorization_error_response("invalid_request", Some("upstream state is required"));
    };
    let transaction = match state
        .auth_store
        .consume_pending_reauth(upstream_state, &provider_id)
    {
        ConsumePendingReauth::Found(transaction) => *transaction,
        ConsumePendingReauth::NotFound => {
            return authorization_error_response(
                "invalid_request",
                Some("upstream state is invalid or expired"),
            );
        }
        ConsumePendingReauth::ProviderMismatch => {
            return authorization_error_response(
                "invalid_request",
                Some("upstream state does not match provider"),
            );
        }
    };

    if let Some(error) = callback.error.as_deref() {
        return authorization_error_redirect(
            &transaction.downstream.redirect_uri,
            map_upstream_authorization_error(error),
            transaction.downstream.state,
        );
    }
    let Some(code) = callback.code.as_deref() else {
        return authorization_error_redirect(
            &transaction.downstream.redirect_uri,
            "server_error",
            transaction.downstream.state,
        );
    };
    let Some(provider) = state.trusted_providers.get(&provider_id) else {
        return authorization_error_redirect(
            &transaction.downstream.redirect_uri,
            "server_error",
            transaction.downstream.state,
        );
    };
    let id_token = match state
        .upstream_client
        .exchange_code(
            provider,
            &transaction.provider_metadata,
            code,
            transaction.pkce_verifier.as_deref(),
        )
        .await
    {
        Ok(id_token) => id_token,
        Err(error) => {
            warn!(provider_id = %provider_id, error = ?error, "upstream token exchange failed");
            return authorization_error_redirect(
                &transaction.downstream.redirect_uri,
                "server_error",
                transaction.downstream.state,
            );
        }
    };
    let identity = match state
        .upstream_client
        .validate_id_token(
            &transaction.provider_metadata,
            provider,
            &id_token,
            &transaction.upstream_nonce,
        )
        .await
    {
        Ok(identity) => identity,
        Err(error) => {
            warn!(provider_id = %provider_id, error = ?error, "upstream id_token validation failed");
            return authorization_error_redirect(
                &transaction.downstream.redirect_uri,
                "server_error",
                transaction.downstream.state,
            );
        }
    };
    let auth_context = AuthContext::ReAuth {
        provider_id: provider_id.clone(),
        upstream_issuer: identity.issuer,
    };
    let user_id = format!("{provider_id}:{}", identity.subject);
    let Some(consent_id) = state.auth_store.create_pending_reauth_consent(
        NewPendingReauthConsent {
            downstream: transaction.downstream,
            user_id,
            auth_context,
        },
        300,
    ) else {
        return authorization_error_response("server_error", None);
    };

    Redirect::to(&format!("/reauth/consent/{consent_id}")).into_response()
}

pub async fn reauth_consent_page(
    State(state): State<AppState>,
    Path(transaction_id): Path<String>,
) -> Response {
    let Some(transaction) = state.auth_store.get_pending_reauth_consent(&transaction_id) else {
        return authorization_error_response(
            "invalid_request",
            Some("re-auth consent is invalid or expired"),
        );
    };
    Html(frontend::reauth_consent_page(
        &transaction.transaction_id,
        &transaction.downstream.client_id,
        transaction.downstream.scope.as_deref().unwrap_or_default(),
        &transaction.user_id,
    ))
    .into_response()
}

pub async fn reauth_consent(
    State(state): State<AppState>,
    Form(form): Form<ReauthConsentForm>,
) -> Response {
    let Some(transaction) = state
        .auth_store
        .consume_pending_reauth_consent(&form.transaction_id)
    else {
        return authorization_error_response(
            "invalid_request",
            Some("re-auth consent is invalid or expired"),
        );
    };
    if form.decision != "approve" {
        return authorization_error_redirect(
            &transaction.downstream.redirect_uri,
            "access_denied",
            transaction.downstream.state,
        );
    }
    issue_authorization_code_redirect_for_downstream(
        &state,
        transaction.downstream,
        transaction.user_id,
        transaction.auth_context,
    )
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
            issue_token(
                &state,
                client,
                scope_text,
                client.client_id.clone(),
                None,
                false,
            )
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
            let scope_text = record.scope;
            let issue_id_token = scope_includes_openid(scope_text.as_deref());
            issue_token(
                &state,
                client,
                scope_text,
                record.user_id,
                record.nonce,
                issue_id_token,
            )
        }
        _ => Err(ApiError::UnsupportedGrantType),
    }
}

fn issue_token(
    state: &AppState,
    client: &Client,
    scope_text: Option<String>,
    subject: String,
    nonce: Option<String>,
    include_id_token: bool,
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

    let access_token = sign_token(state, &claims)?;
    let id_token = if include_id_token {
        Some(build_id_token(
            state,
            client,
            &subject,
            nonce.as_deref(),
            issued_at,
            expires_at,
        )?)
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ttl,
        id_token,
        scope: scope_text,
    }))
}

fn build_id_token(
    state: &AppState,
    client: &Client,
    subject: &str,
    nonce: Option<&str>,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<String, ApiError> {
    let claims = IdTokenClaims {
        iss: state.provider.issuer.as_str(),
        sub: subject,
        aud: client.client_id.as_str(),
        iat: issued_at.timestamp(),
        exp: expires_at.timestamp(),
        nonce,
    };
    sign_token(state, &claims)
}

fn sign_token<T: Serialize>(state: &AppState, claims: &T) -> Result<String, ApiError> {
    let header = state.signing_key.header();
    jsonwebtoken::encode(&header, claims, &state.signing_key.encoding_key)
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))
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

fn validate_authorize_request<'a>(
    state: &'a AppState,
    request: &AuthorizeRequest,
) -> Result<(&'a Client, Option<String>), Box<Response>> {
    let client = state
        .clients
        .get(&request.client_id)
        .ok_or_else(|| Box::new(authorization_error_response("unauthorized_client", None)))?;
    if !client.redirect_uris.contains(&request.redirect_uri) {
        return Err(Box::new(authorization_error_response(
            "invalid_request",
            Some("redirect_uri is not registered for client"),
        )));
    }
    if request.response_type != "code" || !client.response_types.contains("code") {
        return Err(Box::new(authorization_error_redirect(
            &request.redirect_uri,
            "unsupported_response_type",
            request.state.clone(),
        )));
    }
    let scope = validate_scopes(request.scope.as_deref(), client).map_err(|_| {
        Box::new(authorization_error_redirect(
            &request.redirect_uri,
            "invalid_scope",
            request.state.clone(),
        ))
    })?;
    if client.require_pkce && request.code_challenge.is_none() {
        return Err(Box::new(authorization_error_redirect(
            &request.redirect_uri,
            "invalid_request",
            request.state.clone(),
        )));
    }
    if let Some(method) = request.code_challenge_method.as_deref()
        && !matches!(method, "plain" | "S256")
    {
        return Err(Box::new(authorization_error_redirect(
            &request.redirect_uri,
            "invalid_request",
            request.state.clone(),
        )));
    }
    Ok((client, scope))
}

fn scope_includes_openid(scope_text: Option<&str>) -> bool {
    scope_text
        .into_iter()
        .flat_map(str::split_whitespace)
        .any(|scope| scope == "openid")
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

fn requests_fresh_authentication(prompt: Option<&str>) -> bool {
    prompt
        .into_iter()
        .flat_map(str::split_whitespace)
        .any(|value| value == "login")
}

fn random_url_safe_token() -> String {
    // UUID v4 is generated with the operating system's cryptographically secure random source.
    // Three UUIDs give a 96-character verifier, within RFC 7636's 43–128 character range.
    format!(
        "{}{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn map_upstream_authorization_error(error: &str) -> &str {
    match error {
        "access_denied" => "access_denied",
        _ => "temporarily_unavailable",
    }
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
    if let Some(prompt) = request.prompt.as_deref() {
        params.push(format!("prompt={}", encode_uri_component(prompt)));
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
        prompt: None,
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
            "prompt" => request.prompt = Some(value),
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

fn authorization_error_response(error: &str, description: Option<&str>) -> Response {
    #[derive(Serialize)]
    struct ErrorBody<'a> {
        error: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<&'a str>,
    }

    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error,
            error_description: description,
        }),
    )
        .into_response()
}

fn encode_uri_component(value: &str) -> String {
    value.replace(' ', "%20")
}

fn decode_uri_component(value: &str) -> String {
    value.replace("%20", " ")
}
