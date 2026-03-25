use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub username: String,
    pub auth_time: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCodeRecord {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub struct NewAuthorizationCode {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Clone, Default)]
pub struct AuthStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    auth_codes: Arc<RwLock<HashMap<String, AuthorizationCodeRecord>>>,
}

impl AuthStore {
    pub fn create_session(
        &self,
        user_id: String,
        username: String,
        ttl_seconds: i64,
    ) -> Option<Session> {
        let auth_time = Utc::now();
        let expires_at = auth_time.checked_add_signed(Duration::seconds(ttl_seconds))?;
        let session = Session {
            session_id: Uuid::new_v4().to_string(),
            user_id,
            username,
            auth_time,
            expires_at,
        };
        self.sessions
            .write()
            .expect("session lock poisoned")
            .insert(session.session_id.clone(), session.clone());
        Some(session)
    }

    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let now = Utc::now();
        let mut sessions = self.sessions.write().expect("session lock poisoned");
        sessions.retain(|_, session| session.expires_at > now);
        sessions.get(session_id).cloned()
    }

    pub fn issue_authorization_code(
        &self,
        payload: NewAuthorizationCode,
        ttl_seconds: i64,
    ) -> Option<String> {
        let now = Utc::now();
        let expires_at = now.checked_add_signed(Duration::seconds(ttl_seconds))?;
        let code = Uuid::new_v4().to_string();
        let record = AuthorizationCodeRecord {
            code: code.clone(),
            client_id: payload.client_id,
            user_id: payload.user_id,
            redirect_uri: payload.redirect_uri,
            scope: payload.scope,
            nonce: payload.nonce,
            expires_at,
            code_challenge: payload.code_challenge,
            code_challenge_method: payload.code_challenge_method,
        };
        self.auth_codes
            .write()
            .expect("code lock poisoned")
            .insert(code.clone(), record);
        Some(code)
    }

    pub fn consume_authorization_code(&self, code: &str) -> Option<AuthorizationCodeRecord> {
        let now = Utc::now();
        let mut codes = self.auth_codes.write().expect("code lock poisoned");
        codes.retain(|_, record| record.expires_at > now);
        codes.remove(code)
    }
}
