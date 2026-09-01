use std::{
    collections::HashMap,
    fs,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use axum::{
    Form, Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use jsonwebtoken::encode;
use pocket_oid::{app::AppState, crypto::load_signing_key};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use url::Url;
use uuid::Uuid;

use crate::common::{fixture_config_dir, get_json, request, verify_jwt_with_jwks};

#[derive(Clone)]
struct MockOidcState {
    issuer: String,
    signing_key: pocket_oid::crypto::KeyMaterial,
    expected_nonce: Arc<Mutex<Option<String>>>,
    token_forms: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

struct MockOidcProvider {
    issuer: String,
    state: MockOidcState,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

struct TempReauthConfig {
    path: PathBuf,
}

#[tokio::test]
async fn reauth_flow_uses_upstream_identity_then_local_consent() {
    let Some(upstream) = MockOidcProvider::start().await else {
        return;
    };
    let config = TempReauthConfig::new(&upstream.issuer);
    let app = AppState::initialize(config.path())
        .expect("re-auth config should initialize")
        .router();

    let authorize = request(
        app.clone(),
        Request::get(authorize_path(Some("local")))
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER);
    let upstream_url = response_location(&authorize);
    assert!(upstream_url.starts_with(&format!("{}/authorize?", upstream.issuer)));
    let upstream_query = Url::parse(&upstream_url)
        .expect("upstream authorization URL should parse")
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(
        upstream_query.get("response_type"),
        Some(&"code".to_string())
    );
    assert_eq!(
        upstream_query.get("client_id"),
        Some(&"pocket-oid-proxy".to_string())
    );
    assert_eq!(
        upstream_query.get("scope"),
        Some(&"openid email".to_string())
    );
    assert_eq!(
        upstream_query.get("prompt"),
        None,
        "auth_mode must be ignored"
    );
    assert_eq!(
        upstream_query.get("code_challenge_method"),
        Some(&"S256".to_string())
    );
    let upstream_state = upstream_query
        .get("state")
        .expect("upstream state should be present")
        .to_string();
    let upstream_nonce = upstream_query
        .get("nonce")
        .expect("upstream nonce should be present")
        .to_string();
    upstream.expect_nonce(upstream_nonce);

    let callback = request(
        app.clone(),
        Request::get(format!(
            "/reauth/callback/partner?state={upstream_state}&code=upstream-code"
        ))
        .body(Body::empty())
        .expect("request should build"),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let consent_location = response_location(&callback);
    assert!(consent_location.starts_with("/reauth/consent/"));
    let transaction_id = consent_location
        .rsplit('/')
        .next()
        .expect("consent transaction id should be present");

    let consent_page = request(
        app.clone(),
        Request::get(&consent_location)
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(consent_page.status(), StatusCode::OK);
    let page_body = to_bytes(consent_page.into_body(), usize::MAX)
        .await
        .expect("consent page should read");
    assert!(
        String::from_utf8(page_body.to_vec())
            .expect("consent page should be UTF-8")
            .contains("partner:user-123")
    );

    let consent = request(
        app.clone(),
        Request::post("/reauth/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_body(&[
                ("decision", "approve"),
                ("transaction_id", transaction_id),
            ])))
            .expect("request should build"),
    )
    .await;
    assert_eq!(consent.status(), StatusCode::SEE_OTHER);
    let downstream_location = response_location(&consent);
    assert!(downstream_location.starts_with("https://app.example.local/callback?"));
    assert_eq!(
        query_value(&downstream_location, "state").as_deref(),
        Some("downstream-state")
    );
    let code =
        query_value(&downstream_location, "code").expect("downstream code should be present");

    let token = request(
        app.clone(),
        Request::post("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_body(&[
                ("grant_type", "authorization_code"),
                ("client_id", "svc-reauth"),
                ("client_secret", "downstream-secret"),
                ("redirect_uri", "https://app.example.local/callback"),
                ("code", &code),
            ])))
            .expect("request should build"),
    )
    .await;
    assert_eq!(token.status(), StatusCode::OK);
    let token_body = to_bytes(token.into_body(), usize::MAX)
        .await
        .expect("token response should read");
    let token_json: Value =
        serde_json::from_slice(&token_body).expect("token response should parse");
    let (_, jwks) = get_json(app, "/jwks.json").await;
    let claims = verify_jwt_with_jwks(
        token_json["access_token"]
            .as_str()
            .expect("access token should be present"),
        &jwks,
    );
    assert_eq!(claims["sub"], "partner:user-123");
    assert!(claims.get("reauth").is_none());

    let token_forms = upstream.token_forms();
    assert_eq!(token_forms.len(), 1);
    let token_form = &token_forms[0];
    assert_eq!(
        token_form.get("grant_type"),
        Some(&"authorization_code".to_string())
    );
    assert_eq!(token_form.get("code"), Some(&"upstream-code".to_string()));
    assert_eq!(
        token_form.get("client_id"),
        Some(&"pocket-oid-proxy".to_string())
    );
    assert_eq!(
        token_form.get("client_secret"),
        Some(&"upstream-secret".to_string())
    );
    assert!(
        token_form
            .get("code_verifier")
            .is_some_and(|verifier| verifier.len() >= 43)
    );

    upstream.stop().await;
}

#[tokio::test]
async fn upstream_error_uses_the_stored_downstream_redirect() {
    let Some(upstream) = MockOidcProvider::start().await else {
        return;
    };
    let config = TempReauthConfig::new(&upstream.issuer);
    let app = AppState::initialize(config.path())
        .expect("re-auth config should initialize")
        .router();
    let authorize = request(
        app.clone(),
        Request::get(authorize_path(None))
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    let upstream_url = response_location(&authorize);
    let state = query_value(&upstream_url, "state").expect("upstream state should be present");

    let callback = request(
        app,
        Request::get(format!(
            "/reauth/callback/partner?state={state}&error=access_denied"
        ))
        .body(Body::empty())
        .expect("request should build"),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let location = response_location(&callback);
    assert!(location.starts_with("https://app.example.local/callback?"));
    assert_eq!(
        query_value(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        query_value(&location, "state").as_deref(),
        Some("downstream-state")
    );
    assert!(upstream.token_forms().is_empty());

    upstream.stop().await;
}

#[tokio::test]
async fn invalid_upstream_state_does_not_issue_a_code_or_contact_the_provider() {
    let Some(upstream) = MockOidcProvider::start().await else {
        return;
    };
    let config = TempReauthConfig::new(&upstream.issuer);
    let app = AppState::initialize(config.path())
        .expect("re-auth config should initialize")
        .router();

    let callback = request(
        app,
        Request::get("/reauth/callback/partner?state=attacker-state&code=upstream-code")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    assert!(callback.headers().get(header::LOCATION).is_none());
    assert!(upstream.token_forms().is_empty());

    upstream.stop().await;
}

impl MockOidcProvider {
    async fn start() -> Option<Self> {
        let std_listener = match StdTcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("mock upstream listener should bind to loopback: {error}"),
        };
        let addr = std_listener
            .local_addr()
            .expect("mock upstream address should be available");
        std_listener
            .set_nonblocking(true)
            .expect("mock upstream listener should become nonblocking");
        let issuer = format!("http://{addr}");
        let signing_key = load_signing_key(
            &fixture_config_dir("config-basic")
                .join("keys")
                .join("signing-key.pem"),
        )
        .expect("fixture signing key should load");
        let state = MockOidcState {
            issuer: issuer.clone(),
            signing_key,
            expected_nonce: Arc::new(Mutex::new(None)),
            token_forms: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks.json", get(jwks))
            .route("/oauth/token", post(token))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("tokio mock upstream listener should initialize");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("mock upstream server should run");
        });

        Some(Self {
            issuer,
            state,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        })
    }

    fn expect_nonce(&self, nonce: String) {
        *self
            .state
            .expected_nonce
            .lock()
            .expect("nonce lock should not be poisoned") = Some(nonce);
    }

    fn token_forms(&self) -> Vec<HashMap<String, String>> {
        self.state
            .token_forms
            .lock()
            .expect("token form lock should not be poisoned")
            .clone()
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for MockOidcProvider {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl TempReauthConfig {
    fn new(issuer: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pocket-oid-reauth-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("re-auth temp config should be created");
        copy_dir_all(&fixture_config_dir("config-basic"), &path);
        fs::write(
            path.join("clients.json"),
            serde_json::to_vec_pretty(&json!([{
                "client_id": "svc-reauth",
                "client_secret": "downstream-secret",
                "audience": "https://api.example.local",
                "scopes": ["openid", "default"],
                "metadata": {"tenant": "acme"},
                "redirect_uris": ["https://app.example.local/callback"],
                "response_types": ["code"],
                "consent_mode": "skip",
                "auth_mode": "re_auth",
                "re_auth": {
                    "provider_id": "partner",
                    "upstream_scopes": ["openid", "email"],
                    "consent": "local"
                }
            }]))
            .expect("re-auth clients config should serialize"),
        )
        .expect("re-auth clients config should write");
        fs::write(
            path.join("trusted_providers.json"),
            serde_json::to_vec_pretty(&json!([{
                "provider_id": "partner",
                "type": "oidc",
                "issuer": issuer,
                "client_id": "pocket-oid-proxy",
                "client_secret": "upstream-secret",
                "redirect_uri": "https://pocket-oid.local/reauth/callback/partner",
                "token_endpoint_auth_method": "client_secret_post",
                "require_pkce": true
            }]))
            .expect("trusted provider config should serialize"),
        )
        .expect("trusted provider config should write");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempReauthConfig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn discovery(State(state): State<MockOidcState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/oauth/token", state.issuer),
        "jwks_uri": format!("{}/jwks.json", state.issuer)
    }))
}

async fn jwks(State(state): State<MockOidcState>) -> Json<Value> {
    Json(json!({"keys": [state.signing_key.jwk]}))
}

async fn token(
    State(state): State<MockOidcState>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    state
        .token_forms
        .lock()
        .expect("token form lock should not be poisoned")
        .push(form);
    let nonce = state
        .expected_nonce
        .lock()
        .expect("nonce lock should not be poisoned")
        .clone()
        .unwrap_or_else(|| "unexpected-nonce".to_string());
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": state.issuer,
        "sub": "user-123",
        "aud": "pocket-oid-proxy",
        "iat": now,
        "exp": now + 300,
        "nonce": nonce,
        "email": "user@example.test"
    });
    let id_token = encode(
        &state.signing_key.header(),
        &claims,
        &state.signing_key.encoding_key,
    )
    .expect("mock id token should sign");
    Json(json!({
        "access_token": "upstream-access-token-not-forwarded",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token
    }))
}

fn authorize_path(auth_mode: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("response_type", "code");
    query.append_pair("client_id", "svc-reauth");
    query.append_pair("redirect_uri", "https://app.example.local/callback");
    query.append_pair("scope", "openid default");
    query.append_pair("state", "downstream-state");
    query.append_pair("nonce", "downstream-nonce");
    if let Some(auth_mode) = auth_mode {
        query.append_pair("auth_mode", auth_mode);
    }
    format!("/authorize?{}", query.finish())
}

fn form_body(params: &[(&str, &str)]) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        form.append_pair(key, value);
    }
    form.finish()
}

fn response_location(response: &axum::http::Response<Body>) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("response should contain a valid location")
        .to_string()
}

fn query_value(url: &str, name: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .or_else(|| Url::parse(&format!("http://localhost{url}")).ok())?
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("destination directory should be created");
    for entry in fs::read_dir(src).expect("fixture directory should be readable") {
        let entry = entry.expect("fixture entry should read");
        let source_path = entry.path();
        let destination_path = dst.join(entry.file_name());
        if entry
            .metadata()
            .expect("fixture metadata should read")
            .is_dir()
        {
            copy_dir_all(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("fixture file should copy");
        }
    }
}
