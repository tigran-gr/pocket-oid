use axum::Json;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::token::TokenError;

#[derive(Debug, Serialize)]
struct OAuthErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    body: OAuthErrorBody,
    www_authenticate: bool,
}

impl AppError {
    pub fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body: OAuthErrorBody {
                error: "invalid_client".to_string(),
                error_description: Some("client authentication failed".to_string()),
            },
            www_authenticate: true,
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: OAuthErrorBody {
                error: "invalid_request".to_string(),
                error_description: Some(message.into()),
            },
            www_authenticate: false,
        }
    }

    pub fn invalid_scope(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: OAuthErrorBody {
                error: "invalid_scope".to_string(),
                error_description: Some(message.into()),
            },
            www_authenticate: false,
        }
    }

    pub fn unsupported_grant_type() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: OAuthErrorBody {
                error: "unsupported_grant_type".to_string(),
                error_description: Some(
                    "only the client_credentials grant is supported".to_string(),
                ),
            },
            www_authenticate: false,
        }
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: OAuthErrorBody {
                error: "server_error".to_string(),
                error_description: Some(message.into()),
            },
            www_authenticate: false,
        }
    }
}

impl From<TokenError> for AppError {
    fn from(value: TokenError) -> Self {
        match value {
            TokenError::InvalidRequest(msg) => AppError::invalid_request(msg),
            TokenError::InvalidScope(msg) => AppError::invalid_scope(msg),
            TokenError::ClaimConstruction(msg) => AppError::server_error(msg),
            TokenError::Signing => AppError::server_error("failed to sign access token"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body)).into_response();
        if self.www_authenticate {
            if let Ok(value) = HeaderValue::from_str("Basic realm=\"OAuth\"") {
                response
                    .headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}
