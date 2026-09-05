use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::{config::ReAuthConsent, upstream::DiscoveredOidcProvider};

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
    pub auth_context: AuthContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthContext {
    Local,
    ReAuth {
        provider_id: String,
        upstream_issuer: String,
    },
}

pub struct NewAuthorizationCode {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub auth_context: AuthContext,
}

#[derive(Debug, Clone)]
pub struct DownstreamAuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingReauthTransaction {
    pub downstream: DownstreamAuthorizationRequest,
    pub provider_id: String,
    pub consent: ReAuthConsent,
    pub upstream_state: String,
    pub upstream_nonce: String,
    pub pkce_verifier: Option<String>,
    pub provider_metadata: DiscoveredOidcProvider,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewPendingReauthTransaction {
    pub downstream: DownstreamAuthorizationRequest,
    pub provider_id: String,
    pub consent: ReAuthConsent,
    pub upstream_state: String,
    pub upstream_nonce: String,
    pub pkce_verifier: Option<String>,
    pub provider_metadata: DiscoveredOidcProvider,
}

#[derive(Debug, Clone)]
pub struct PendingReauthConsent {
    pub transaction_id: String,
    pub downstream: DownstreamAuthorizationRequest,
    pub user_id: String,
    pub auth_context: AuthContext,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewPendingReauthConsent {
    pub downstream: DownstreamAuthorizationRequest,
    pub user_id: String,
    pub auth_context: AuthContext,
}

#[derive(Debug, Clone)]
pub enum ConsumePendingReauth {
    Found(Box<PendingReauthTransaction>),
    NotFound,
    ProviderMismatch,
}

#[derive(Clone, Default)]
pub struct AuthStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    auth_codes: Arc<RwLock<HashMap<String, AuthorizationCodeRecord>>>,
    pending_reauth: Arc<RwLock<HashMap<String, PendingReauthTransaction>>>,
    pending_reauth_consents: Arc<RwLock<HashMap<String, PendingReauthConsent>>>,
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
            auth_context: payload.auth_context,
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

    pub fn create_pending_reauth(
        &self,
        payload: NewPendingReauthTransaction,
        ttl_seconds: i64,
    ) -> Option<()> {
        let created_at = Utc::now();
        let expires_at = created_at.checked_add_signed(Duration::seconds(ttl_seconds))?;
        let transaction = PendingReauthTransaction {
            downstream: payload.downstream,
            provider_id: payload.provider_id,
            consent: payload.consent,
            upstream_state: payload.upstream_state.clone(),
            upstream_nonce: payload.upstream_nonce,
            pkce_verifier: payload.pkce_verifier,
            provider_metadata: payload.provider_metadata,
            created_at,
            expires_at,
        };
        let mut transactions = self
            .pending_reauth
            .write()
            .expect("re-auth transaction lock poisoned");
        transactions.retain(|_, value| value.expires_at > created_at);
        if transactions.contains_key(&payload.upstream_state) {
            return None;
        }
        transactions.insert(payload.upstream_state, transaction);
        Some(())
    }

    pub fn consume_pending_reauth(
        &self,
        upstream_state: &str,
        provider_id: &str,
    ) -> ConsumePendingReauth {
        let now = Utc::now();
        let mut transactions = self
            .pending_reauth
            .write()
            .expect("re-auth transaction lock poisoned");
        transactions.retain(|_, value| value.expires_at > now);
        let Some(transaction) = transactions.get(upstream_state) else {
            return ConsumePendingReauth::NotFound;
        };
        if transaction.provider_id != provider_id {
            return ConsumePendingReauth::ProviderMismatch;
        }
        let transaction = transactions
            .remove(upstream_state)
            .expect("transaction was present immediately before removal");
        ConsumePendingReauth::Found(Box::new(transaction))
    }

    pub fn create_pending_reauth_consent(
        &self,
        payload: NewPendingReauthConsent,
        ttl_seconds: i64,
    ) -> Option<String> {
        let now = Utc::now();
        let expires_at = now.checked_add_signed(Duration::seconds(ttl_seconds))?;
        let transaction_id = Uuid::new_v4().to_string();
        let transaction = PendingReauthConsent {
            transaction_id: transaction_id.clone(),
            downstream: payload.downstream,
            user_id: payload.user_id,
            auth_context: payload.auth_context,
            expires_at,
        };
        let mut consents = self
            .pending_reauth_consents
            .write()
            .expect("re-auth consent lock poisoned");
        consents.retain(|_, value| value.expires_at > now);
        consents.insert(transaction_id.clone(), transaction);
        Some(transaction_id)
    }

    pub fn get_pending_reauth_consent(&self, transaction_id: &str) -> Option<PendingReauthConsent> {
        let now = Utc::now();
        let mut consents = self
            .pending_reauth_consents
            .write()
            .expect("re-auth consent lock poisoned");
        consents.retain(|_, value| value.expires_at > now);
        consents.get(transaction_id).cloned()
    }

    pub fn consume_pending_reauth_consent(
        &self,
        transaction_id: &str,
    ) -> Option<PendingReauthConsent> {
        let now = Utc::now();
        let mut consents = self
            .pending_reauth_consents
            .write()
            .expect("re-auth consent lock poisoned");
        consents.retain(|_, value| value.expires_at > now);
        consents.remove(transaction_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthStore, ConsumePendingReauth, DownstreamAuthorizationRequest,
        NewPendingReauthTransaction,
    };
    use crate::{config::ReAuthConsent, upstream::DiscoveredOidcProvider};

    fn pending_transaction(state: &str) -> NewPendingReauthTransaction {
        NewPendingReauthTransaction {
            downstream: DownstreamAuthorizationRequest {
                client_id: "svc-a".to_string(),
                redirect_uri: "https://app.example.test/callback".to_string(),
                scope: Some("openid".to_string()),
                state: Some("downstream-state".to_string()),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
            },
            provider_id: "partner".to_string(),
            consent: ReAuthConsent::Local,
            upstream_state: state.to_string(),
            upstream_nonce: "upstream-nonce".to_string(),
            pkce_verifier: Some("upstream-verifier".to_string()),
            provider_metadata: DiscoveredOidcProvider {
                issuer: "https://partner.example.test".to_string(),
                authorization_endpoint: "https://partner.example.test/authorize".to_string(),
                token_endpoint: "https://partner.example.test/oauth/token".to_string(),
                jwks_uri: "https://partner.example.test/jwks.json".to_string(),
            },
        }
    }

    #[test]
    fn pending_reauth_transactions_are_provider_bound_and_single_use() {
        let store = AuthStore::default();
        store
            .create_pending_reauth(pending_transaction("upstream-state"), 60)
            .expect("transaction should be created");

        assert!(matches!(
            store.consume_pending_reauth("upstream-state", "other-provider"),
            ConsumePendingReauth::ProviderMismatch
        ));
        assert!(matches!(
            store.consume_pending_reauth("upstream-state", "partner"),
            ConsumePendingReauth::Found(_)
        ));
        assert!(matches!(
            store.consume_pending_reauth("upstream-state", "partner"),
            ConsumePendingReauth::NotFound
        ));
    }

    #[test]
    fn expired_pending_reauth_transactions_are_not_consumed() {
        let store = AuthStore::default();
        store
            .create_pending_reauth(pending_transaction("expired-state"), -1)
            .expect("transaction should be created");

        assert!(matches!(
            store.consume_pending_reauth("expired-state", "partner"),
            ConsumePendingReauth::NotFound
        ));
    }
}
