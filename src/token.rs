use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Number, Value};
use uuid::Uuid;

use crate::{config::Client, error::AppError};

#[derive(Clone)]
pub struct TokenTemplate {
    raw: Value,
}

#[derive(Debug)]
pub struct TokenContext<'a> {
    pub client: &'a Client,
    pub scope: Option<&'a str>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub audience: Option<&'a str>,
    pub uuid: Uuid,
}

impl TokenTemplate {
    pub fn new(raw: Value) -> Self {
        Self { raw }
    }

    pub fn render(&self, ctx: &TokenContext<'_>) -> Result<Value, AppError> {
        let mut value = self.raw.clone();
        substitute_value(&mut value, ctx)?;
        ensure_required_claims(&value)?;
        Ok(value)
    }
}

fn substitute_value(value: &mut Value, ctx: &TokenContext<'_>) -> Result<(), AppError> {
    match value {
        Value::Object(map) => {
            for val in map.values_mut() {
                substitute_value(val, ctx)?;
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                substitute_value(item, ctx)?;
            }
        }
        Value::String(text) => {
            if let Some(placeholder) = extract_placeholder(text) {
                let replacement = resolve_placeholder(&placeholder, ctx)?;
                *value = replacement;
                return Ok(());
            }

            let mut rendered = text.clone();
            while let Some(start) = rendered.find("${") {
                let end = rendered[start + 2..]
                    .find('}')
                    .map(|idx| idx + start + 3)
                    .ok_or_else(|| {
                        AppError::Template(format!(
                            "unterminated placeholder in template value: {text}"
                        ))
                    })?;
                let name = &rendered[start + 2..end - 1];
                let replacement = resolve_placeholder(name, ctx)?;
                let replacement_text = value_to_string(&replacement).ok_or_else(|| {
                    AppError::Template(format!("placeholder {name} cannot be rendered inline"))
                })?;
                rendered.replace_range(start..end, &replacement_text);
            }
            *value = Value::String(rendered);
        }
        _ => {}
    }
    Ok(())
}

fn extract_placeholder(value: &str) -> Option<String> {
    if value.starts_with("${") && value.ends_with('}') && value.len() > 3 {
        Some(value[2..value.len() - 1].to_string())
    } else {
        None
    }
}

fn resolve_placeholder(name: &str, ctx: &TokenContext<'_>) -> Result<Value, AppError> {
    match name {
        "client_id" => Ok(Value::String(ctx.client.client_id.clone())),
        "audience" => ctx
            .audience
            .map(|aud| Value::String(aud.to_string()))
            .ok_or_else(|| {
                AppError::Template("audience placeholder requires client audience".into())
            }),
        "scope" => Ok(Value::String(ctx.scope.unwrap_or("").to_string())),
        "issued_at" => Ok(Value::Number(Number::from(ctx.issued_at.timestamp()))),
        "expires_at" => Ok(Value::Number(Number::from(ctx.expires_at.timestamp()))),
        "uuid" => Ok(Value::String(ctx.uuid.to_string())),
        placeholder if placeholder.starts_with("metadata.") => {
            let key = &placeholder[9..];
            resolve_metadata_value(key, &ctx.client.metadata)
        }
        other => Err(AppError::Template(format!(
            "unsupported placeholder '{other}' in token template"
        ))),
    }
}

fn resolve_metadata_value(
    key: &str,
    metadata: &BTreeMap<String, Value>,
) -> Result<Value, AppError> {
    metadata
        .get(key)
        .cloned()
        .ok_or_else(|| AppError::Template(format!("missing metadata value for '{key}'")))
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(num) => Some(num.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn ensure_required_claims(value: &Value) -> Result<(), AppError> {
    let required = ["iss", "sub", "aud", "iat", "exp", "jti"];
    let map = value
        .as_object()
        .ok_or_else(|| AppError::Template("token template must render to a JSON object".into()))?;
    for claim in required {
        if !map.contains_key(claim) {
            return Err(AppError::Template(format!(
                "rendered token missing required claim '{claim}'"
            )));
        }
    }
    Ok(())
}
