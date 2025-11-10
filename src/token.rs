use std::collections::HashSet;

use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::config::Client;
use crate::key::KeyStore;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("{0}")]
    InvalidRequest(String),
    #[error("{0}")]
    InvalidScope(String),
    #[error("failed to build token claims: {0}")]
    ClaimConstruction(String),
    #[error("signing failure")]
    Signing,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct TokenService {
    issuer: String,
    ttl: Duration,
    template: Value,
    key_store: KeyStore,
}

impl TokenService {
    pub fn new(
        issuer: String,
        ttl_secs: std::time::Duration,
        template: Value,
        key_store: KeyStore,
    ) -> Self {
        Self {
            issuer,
            ttl: Duration::seconds(ttl_secs.as_secs() as i64),
            template,
            key_store,
        }
    }

    pub fn issue_token(
        &self,
        client: &Client,
        requested_scopes: &[String],
    ) -> Result<TokenResponse, TokenError> {
        let issued_at = Utc::now();
        let expires_at = issued_at + self.ttl;
        let jti = Uuid::new_v4().to_string();

        let scope_set = if requested_scopes.is_empty() {
            if let Some(default_scope) = &client.default_scope {
                parse_scope(Some(default_scope.clone()))
            } else if client.scopes.is_empty() {
                Vec::new()
            } else {
                client.scopes.clone()
            }
        } else {
            validate_scopes(requested_scopes, &client.scopes)?;
            requested_scopes.to_vec()
        };
        let scope_string = scope_set.join(" ");

        let ctx = TemplateContext {
            issuer: &self.issuer,
            client,
            scope: &scope_string,
            issued_at: issued_at.timestamp(),
            expires_at: expires_at.timestamp(),
            jti: &jti,
        };

        let claims = apply_template(&self.template, &ctx)
            .map_err(|err| TokenError::ClaimConstruction(err.to_string()))?;

        ensure_required_claims(&claims).map_err(|err| TokenError::ClaimConstruction(err))?;

        let token = self
            .key_store
            .primary()
            .sign(&claims)
            .map_err(|_| TokenError::Signing)?;

        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.ttl.num_seconds(),
            scope: scope_string,
        })
    }
}

fn validate_scopes(requested: &[String], allowed: &[String]) -> Result<(), TokenError> {
    if allowed.is_empty() {
        return Ok(());
    }
    let allowed_set: HashSet<&str> = allowed.iter().map(|s| s.as_str()).collect();
    for scope in requested {
        if !allowed_set.contains(scope.as_str()) {
            return Err(TokenError::InvalidScope(format!(
                "requested scope '{scope}' is not permitted for this client"
            )));
        }
    }
    Ok(())
}

struct TemplateContext<'a> {
    issuer: &'a str,
    client: &'a Client,
    scope: &'a str,
    issued_at: i64,
    expires_at: i64,
    jti: &'a str,
}

fn apply_template(template: &Value, ctx: &TemplateContext<'_>) -> Result<Value> {
    match template {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(template.clone()),
        Value::String(text) => substitute_string(text, ctx),
        Value::Array(items) => {
            let mut result = Vec::with_capacity(items.len());
            for item in items {
                result.push(apply_template(item, ctx)?);
            }
            Ok(Value::Array(result))
        }
        Value::Object(map) => {
            let mut result = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                result.insert(key.clone(), apply_template(value, ctx)?);
            }
            Ok(Value::Object(result))
        }
    }
}

fn substitute_string(value: &str, ctx: &TemplateContext<'_>) -> Result<Value> {
    if !value.contains("${") {
        return Ok(Value::String(value.to_string()));
    }

    if let Some(placeholder) = extract_placeholder(value) {
        if value.trim() == placeholder {
            let key = placeholder.trim_start_matches("${").trim_end_matches("}");
            if let Some(resolved) = resolve_placeholder(key, ctx) {
                return Ok(resolved);
            } else {
                return Err(anyhow!("unknown placeholder '{key}' in token template"));
            }
        }
    }

    let mut rendered = value.to_string();
    let mut cursor = 0;
    while let Some(start) = rendered[cursor..].find("${") {
        let global_start = cursor + start;
        if let Some(end) = rendered[global_start..].find('}') {
            let global_end = global_start + end;
            let key = &rendered[global_start + 2..global_end];
            if let Some(resolved) = resolve_placeholder(key, ctx) {
                rendered.replace_range(global_start..=global_end, &resolved_to_string(resolved));
                cursor = global_start;
            } else {
                cursor = global_end + 1;
            }
        } else {
            break;
        }
    }
    Ok(Value::String(rendered))
}

fn extract_placeholder(value: &str) -> Option<&str> {
    if value.starts_with("${") && value.ends_with('}') {
        Some(value)
    } else {
        None
    }
}

fn resolve_placeholder(key: &str, ctx: &TemplateContext<'_>) -> Option<Value> {
    match key {
        "issuer" => Some(Value::String(ctx.issuer.to_string())),
        "client_id" => Some(Value::String(ctx.client.client_id.clone())),
        "audience" => Some(Value::String(ctx.client.audience.clone())),
        "scope" => Some(Value::String(ctx.scope.to_string())),
        "issued_at" => Some(json!(ctx.issued_at)),
        "expires_at" => Some(json!(ctx.expires_at)),
        "uuid" | "jti" => Some(Value::String(ctx.jti.to_string())),
        "tenant" => lookup_metadata("tenant", ctx),
        _ if key.starts_with("metadata.") => {
            let path = &key[9..];
            lookup_metadata(path, ctx)
        }
        _ => None,
    }
}

fn lookup_metadata(path: &str, ctx: &TemplateContext<'_>) -> Option<Value> {
    let mut cursor = &ctx.client.metadata;
    if cursor.is_null() {
        return None;
    }
    for segment in path.split('.') {
        match cursor {
            Value::Object(map) => {
                cursor = map.get(segment)?;
            }
            _ => return None,
        }
    }
    Some(cursor.clone())
}

fn resolved_to_string(value: Value) -> String {
    match value {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

fn ensure_required_claims(claims: &Value) -> Result<(), String> {
    let required = ["iss", "sub", "aud", "iat", "exp", "jti"];
    let obj = claims
        .as_object()
        .ok_or_else(|| "token template must produce a JSON object".to_string())?;
    for key in required {
        let value = obj
            .get(key)
            .ok_or_else(|| format!("token template is missing required claim '{key}'"))?;
        if matches!(value, Value::String(s) if s.contains("${")) {
            return Err(format!("token template is missing required claim '{key}'"));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scope: Option<String>,
}

pub fn parse_scope(value: Option<String>) -> Vec<String> {
    value
        .map(|s| {
            s.split_whitespace()
                .filter(|scope| !scope.is_empty())
                .map(|scope| scope.to_string())
                .collect()
        })
        .unwrap_or_default()
}
