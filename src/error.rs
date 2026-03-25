use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema validation error: {0}")]
    Schema(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("template error: {0}")]
    Template(String),
}

#[derive(Debug)]
pub enum ApiError {
    InvalidClient,
    InvalidGrant(String),
    InvalidRequest(String),
    InvalidScope(String),
    UnsupportedGrantType,
    Internal(anyhow::Error),
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl ApiError {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest(message.into())
    }

    pub fn invalid_grant(message: impl Into<String>) -> Self {
        Self::InvalidGrant(message.into())
    }

    pub fn invalid_scope(message: impl Into<String>) -> Self {
        Self::InvalidScope(message.into())
    }

    pub fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::InvalidClient => {
                build_response(StatusCode::UNAUTHORIZED, "invalid_client", None)
            }
            ApiError::InvalidGrant(desc) => {
                build_response(StatusCode::BAD_REQUEST, "invalid_grant", Some(desc))
            }
            ApiError::InvalidRequest(desc) => {
                build_response(StatusCode::BAD_REQUEST, "invalid_request", Some(desc))
            }
            ApiError::InvalidScope(desc) => {
                build_response(StatusCode::BAD_REQUEST, "invalid_scope", Some(desc))
            }
            ApiError::UnsupportedGrantType => build_response(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                Some(
                    "supported grant types are client_credentials and authorization_code"
                        .to_string(),
                ),
            ),
            ApiError::Internal(err) => {
                error!(error = ?err, "internal server error");
                build_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("internal server error".to_string()),
                )
            }
        }
    }
}

fn build_response(status: StatusCode, error: &str, description: Option<String>) -> Response {
    let body = ErrorBody {
        error: error.to_string(),
        error_description: description,
    };
    (status, Json(body)).into_response()
}
