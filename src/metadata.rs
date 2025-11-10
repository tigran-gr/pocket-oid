use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

pub fn discovery_document(base_issuer: &str) -> DiscoveryDocument {
    let base = base_issuer.trim_end_matches('/');
    DiscoveryDocument {
        issuer: base.to_string(),
        token_endpoint: format!("{}/oauth/token", base),
        jwks_uri: format!("{}/jwks.json", base),
        grant_types_supported: vec!["client_credentials".to_string()],
        response_types_supported: vec!["token".to_string()],
        subject_types_supported: vec!["public".to_string()],
        token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
    }
}
