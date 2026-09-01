use std::time::Duration;

use anyhow::{Context, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::Value;
use subtle::ConstantTimeEq;
use url::Url;

use crate::{config::TrustedProviderConfig, error::AppError};

const CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Clone)]
pub struct UpstreamClient {
    http: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct DiscoveredOidcProvider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedUpstreamIdentity {
    pub subject: String,
    pub issuer: String,
}

pub struct UpstreamAuthorizationRequest<'a> {
    pub provider: &'a TrustedProviderConfig,
    pub metadata: &'a DiscoveredOidcProvider,
    pub upstream_scopes: &'a [String],
    pub state: &'a str,
    pub nonce: &'a str,
    pub pkce_verifier: Option<&'a str>,
    pub prompt_login: bool,
}

#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct UpstreamTokenResponse {
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RemoteJwkSet {
    keys: Vec<RemoteJwk>,
}

#[derive(Debug, Deserialize)]
struct RemoteJwk {
    kty: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    alg: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

impl UpstreamClient {
    pub fn new() -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .user_agent("pocket-oid/0.1")
            .build()
            .map_err(|error| {
                AppError::Config(format!("failed to configure HTTP client: {error}"))
            })?;
        Ok(Self { http })
    }

    pub async fn discover(
        &self,
        provider: &TrustedProviderConfig,
    ) -> anyhow::Result<DiscoveredOidcProvider> {
        let discovery_url = discovery_url(&provider.issuer)?;
        let response = self
            .http
            .get(discovery_url.clone())
            .send()
            .await
            .with_context(|| {
                format!("failed to fetch OIDC discovery metadata from {discovery_url}")
            })?;
        if !response.status().is_success() {
            bail!(
                "OIDC discovery endpoint {discovery_url} returned HTTP {}",
                response.status()
            );
        }
        let document: DiscoveryResponse = response.json().await.with_context(|| {
            format!("OIDC discovery metadata from {discovery_url} was not valid JSON")
        })?;
        if document.issuer != provider.issuer {
            bail!(
                "OIDC discovery issuer '{}' does not exactly match configured issuer '{}'",
                document.issuer,
                provider.issuer
            );
        }
        validate_endpoint(&document.authorization_endpoint, "authorization_endpoint")?;
        validate_endpoint(&document.token_endpoint, "token_endpoint")?;
        validate_endpoint(&document.jwks_uri, "jwks_uri")?;

        Ok(DiscoveredOidcProvider {
            issuer: document.issuer,
            authorization_endpoint: document.authorization_endpoint,
            token_endpoint: document.token_endpoint,
            jwks_uri: document.jwks_uri,
        })
    }

    pub fn build_authorization_url(
        &self,
        request: UpstreamAuthorizationRequest<'_>,
    ) -> anyhow::Result<String> {
        let mut url = Url::parse(&request.metadata.authorization_endpoint)
            .context("discovered authorization_endpoint must be a valid URL")?;
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &request.provider.client_id);
        query.append_pair("redirect_uri", &request.provider.redirect_uri);
        query.append_pair("scope", &request.upstream_scopes.join(" "));
        query.append_pair("state", request.state);
        query.append_pair("nonce", request.nonce);
        if let Some(verifier) = request.pkce_verifier {
            query.append_pair("code_challenge", &pkce_challenge(verifier));
            query.append_pair("code_challenge_method", "S256");
        }
        if request.prompt_login {
            query.append_pair("prompt", "login");
        }
        drop(query);
        Ok(url.into())
    }

    pub async fn exchange_code(
        &self,
        provider: &TrustedProviderConfig,
        metadata: &DiscoveredOidcProvider,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> anyhow::Result<String> {
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", provider.redirect_uri.clone()),
            ("client_id", provider.client_id.clone()),
            ("client_secret", provider.client_secret.clone()),
        ];
        if let Some(verifier) = pkce_verifier {
            form.push(("code_verifier", verifier.to_string()));
        }

        let response = self
            .http
            .post(&metadata.token_endpoint)
            .form(&form)
            .send()
            .await
            .context("failed to exchange upstream authorization code")?;
        if !response.status().is_success() {
            bail!(
                "upstream token endpoint returned HTTP {}",
                response.status()
            );
        }
        let tokens: UpstreamTokenResponse = response
            .json()
            .await
            .context("upstream token endpoint returned invalid JSON")?;
        tokens
            .id_token
            .filter(|token| !token.is_empty())
            .context("upstream token response did not include an id_token")
    }

    pub async fn validate_id_token(
        &self,
        metadata: &DiscoveredOidcProvider,
        provider: &TrustedProviderConfig,
        id_token: &str,
        expected_nonce: &str,
    ) -> anyhow::Result<ValidatedUpstreamIdentity> {
        let header = decode_header(id_token).context("upstream id_token has an invalid header")?;
        if header.alg != Algorithm::RS256 {
            bail!("upstream id_token must use RS256");
        }
        let kid = header
            .kid
            .context("upstream id_token header is missing kid")?;
        let keys = self.fetch_jwks(&metadata.jwks_uri).await?;
        let jwk = keys
            .keys
            .into_iter()
            .find(|key| key.kid.as_deref() == Some(kid.as_str()))
            .context("upstream id_token kid was not found in JWKS")?;
        if jwk.kty.as_deref() != Some("RSA")
            || !matches!(jwk.key_use.as_deref(), None | Some("sig"))
            || !matches!(jwk.alg.as_deref(), None | Some("RS256"))
        {
            bail!("upstream JWKS key is not an RS256 signing key");
        }
        let modulus = jwk.n.context("upstream JWKS key is missing modulus")?;
        let exponent = jwk.e.context("upstream JWKS key is missing exponent")?;
        let decoding_key = DecodingKey::from_rsa_components(&modulus, &exponent)
            .context("upstream JWKS key is invalid")?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = CLOCK_SKEW_SECONDS as u64;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&[&metadata.issuer]);
        validation.set_audience(&[&provider.client_id]);
        let claims = decode::<Value>(id_token, &decoding_key, &validation)
            .context("upstream id_token failed signature or standard-claim validation")?
            .claims;

        let issued_at = claims
            .get("iat")
            .and_then(Value::as_i64)
            .context("upstream id_token is missing a numeric iat claim")?;
        if issued_at > chrono::Utc::now().timestamp() + CLOCK_SKEW_SECONDS {
            bail!("upstream id_token iat is in the future");
        }
        let nonce = claims
            .get("nonce")
            .and_then(Value::as_str)
            .context("upstream id_token is missing nonce")?;
        if !constant_time_eq(nonce, expected_nonce) {
            bail!("upstream id_token nonce does not match");
        }
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|subject| !subject.is_empty())
            .context("upstream id_token is missing a non-empty sub claim")?;

        Ok(ValidatedUpstreamIdentity {
            subject: subject.to_string(),
            issuer: metadata.issuer.clone(),
        })
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> anyhow::Result<RemoteJwkSet> {
        let response = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .with_context(|| format!("failed to fetch upstream JWKS from {jwks_uri}"))?;
        if !response.status().is_success() {
            bail!(
                "upstream JWKS endpoint {jwks_uri} returned HTTP {}",
                response.status()
            );
        }
        response
            .json()
            .await
            .context("upstream JWKS response was not valid JSON")
    }
}

fn discovery_url(issuer: &str) -> anyhow::Result<String> {
    validate_endpoint(issuer, "issuer")?;
    Ok(format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
}

fn validate_endpoint(value: &str, field: &str) -> anyhow::Result<()> {
    let url = Url::parse(value).with_context(|| format!("{field} is not a valid URL"))?;
    if url.host_str().is_none() || url.fragment().is_some() {
        bail!("{field} must be an absolute URL without a fragment");
    }
    Ok(())
}

fn pkce_challenge(verifier: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::{DiscoveredOidcProvider, UpstreamAuthorizationRequest, UpstreamClient};
    use crate::config::{TokenEndpointAuthMethod, TrustedProviderConfig, TrustedProviderType};

    #[test]
    fn authorization_url_contains_oidc_and_pkce_parameters() {
        let client = UpstreamClient::new().expect("HTTP client should initialize");
        let provider = TrustedProviderConfig {
            provider_id: "partner".to_string(),
            provider_type: TrustedProviderType::Oidc,
            issuer: "https://partner.example.test".to_string(),
            client_id: "proxy".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://pocket.example.test/reauth/callback/partner".to_string(),
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            require_pkce: true,
        };
        let metadata = DiscoveredOidcProvider {
            issuer: provider.issuer.clone(),
            authorization_endpoint: "https://partner.example.test/authorize".to_string(),
            token_endpoint: "https://partner.example.test/oauth/token".to_string(),
            jwks_uri: "https://partner.example.test/jwks.json".to_string(),
        };

        let url = client
            .build_authorization_url(UpstreamAuthorizationRequest {
                provider: &provider,
                metadata: &metadata,
                upstream_scopes: &["openid".to_string(), "email".to_string()],
                state: "upstream-state",
                nonce: "upstream-nonce",
                pkce_verifier: Some("test-verifier"),
                prompt_login: true,
            })
            .expect("authorization URL should build");

        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=proxy"));
        assert!(url.contains("state=upstream-state"));
        assert!(url.contains("nonce=upstream-nonce"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("prompt=login"));
    }
}
