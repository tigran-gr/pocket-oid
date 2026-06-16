use std::{
    collections::HashMap,
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::{Request, StatusCode, Uri, header},
    response::Html,
    routing::get,
};
use chrono::Utc;
use pocket_oid::app::AppState;
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use uuid::Uuid;

use crate::common::{
    fixture_config_dir, get_json, request, test_app, verify_jwt_with_jwks, verify_jwt_with_jwks_for,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct CallbackRecord {
    path: String,
    query: String,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Clone, Default)]
struct ListenerState {
    records: Arc<Mutex<Vec<CallbackRecord>>>,
}

struct LoopbackListener {
    addr: SocketAddr,
    records: Arc<Mutex<Vec<CallbackRecord>>>,
    app: Option<Router>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

struct TempConfigDir {
    path: PathBuf,
}

#[tokio::test]
async fn completes_authorization_code_flow() {
    let app = test_app("config-basic");
    let authorize_path = build_authorize_path(
        "svc-a",
        "https://app.example.local/callback",
        "default",
        Some("abc"),
        None,
    );

    let authorize = request(
        app.clone(),
        Request::get(&authorize_path)
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(authorize.status(), StatusCode::OK);

    let login = request(
        app.clone(),
        Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_body(&[
                ("username", "alice"),
                ("password", "password123"),
                ("return_to", &authorize_path),
            ])))
            .expect("request should build"),
    )
    .await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let session_cookie = session_cookie(&login);

    let authorize_with_session = request(
        app.clone(),
        Request::get(&authorize_path)
            .header(header::COOKIE, session_cookie.clone())
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(authorize_with_session.status(), StatusCode::OK);

    let consent = request(
        app.clone(),
        Request::post("/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, session_cookie)
            .body(Body::from(form_body(&[
                ("decision", "approve"),
                ("return_to", &authorize_path),
            ])))
            .expect("request should build"),
    )
    .await;
    assert_eq!(consent.status(), StatusCode::SEE_OTHER);

    let location = consent
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location should be present");
    let code = query_value(location, "code").expect("code should be present");

    let token_response = request(
        app.clone(),
        Request::post("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_body(&[
                ("grant_type", "authorization_code"),
                ("client_id", "svc-a"),
                ("client_secret", "supersecret"),
                ("redirect_uri", "https://app.example.local/callback"),
                ("code", &code),
            ])))
            .expect("request should build"),
    )
    .await;

    assert_eq!(token_response.status(), StatusCode::OK);
    let body = to_bytes(token_response.into_body(), usize::MAX)
        .await
        .expect("response body should read");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json should parse");
    assert!(json.get("id_token").is_none());

    let token = json["access_token"]
        .as_str()
        .expect("token should be present");
    let (_, jwks) = get_json(app, "/jwks.json").await;
    let claims = verify_jwt_with_jwks(token, &jwks);
    assert_eq!(claims["sub"], "user-alice");
}

#[tokio::test]
async fn completes_code_flow_with_loopback_listener_and_id_token_verification() {
    let listener = LoopbackListener::start().await;
    let redirect_uri = listener.redirect_uri();
    let config_dir = TempConfigDir::with_loopback_redirect(&redirect_uri);
    let app = AppState::initialize(config_dir.path())
        .expect("app state should initialize")
        .router();

    let state = format!("state-{}", Uuid::new_v4());
    let nonce = format!("nonce-{}", Uuid::new_v4());
    let authorize_path = build_authorize_path(
        "svc-a",
        &redirect_uri,
        "openid default",
        Some(&state),
        Some(&nonce),
    );

    let authorize = request(
        app.clone(),
        Request::get(&authorize_path)
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(authorize.status(), StatusCode::OK);

    let login = request(
        app.clone(),
        Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_body(&[
                ("username", "alice"),
                ("password", "password123"),
                ("return_to", &authorize_path),
            ])))
            .expect("request should build"),
    )
    .await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let session_cookie = session_cookie(&login);

    let authorize_with_session = request(
        app.clone(),
        Request::get(&authorize_path)
            .header(header::COOKIE, session_cookie.clone())
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(authorize_with_session.status(), StatusCode::OK);

    let consent = request(
        app.clone(),
        Request::post("/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, session_cookie)
            .body(Body::from(form_body(&[
                ("decision", "approve"),
                ("return_to", &authorize_path),
            ])))
            .expect("request should build"),
    )
    .await;
    assert_eq!(consent.status(), StatusCode::SEE_OTHER);

    let location = consent
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location should be present");
    assert!(
        location.starts_with(&redirect_uri),
        "redirect should target the loopback listener"
    );

    let (listener_status, listener_body) = listener.dispatch(location).await;
    assert_eq!(listener_status, StatusCode::OK);
    assert!(listener_body.contains("Authentication successful, you can close this browser tab."));

    let records = listener.records();
    assert_eq!(records.len(), 1);
    let callback = &records[0];
    assert_eq!(callback.path, "/callback");
    assert_eq!(callback.state.as_deref(), Some(state.as_str()));
    assert!(callback.code.as_deref().is_some());
    assert!(callback.error.is_none());

    let code = callback.code.clone().expect("callback code should exist");
    let token_response = request(
        app.clone(),
        Request::post("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form_body(&[
                ("grant_type", "authorization_code"),
                ("client_id", "svc-a"),
                ("client_secret", "supersecret"),
                ("redirect_uri", &redirect_uri),
                ("code", &code),
            ])))
            .expect("request should build"),
    )
    .await;

    assert_eq!(token_response.status(), StatusCode::OK);
    let body = to_bytes(token_response.into_body(), usize::MAX)
        .await
        .expect("response body should read");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json should parse");
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["scope"], "openid default");
    assert!(json["access_token"].as_str().is_some());
    let id_token = json["id_token"]
        .as_str()
        .expect("id_token should be present for openid scope");

    let (_, discovery) = get_json(app.clone(), "/.well-known/openid-configuration").await;
    let issuer = discovery["issuer"]
        .as_str()
        .expect("issuer should be present");
    let jwks_uri = discovery["jwks_uri"]
        .as_str()
        .expect("jwks_uri should be present");
    let (_, jwks) = get_json(app, &path_from_url(jwks_uri)).await;

    let claims = verify_jwt_with_jwks_for(id_token, &jwks, issuer, "svc-a");
    let now = Utc::now().timestamp();
    let issued_at = claims["iat"]
        .as_i64()
        .expect("iat should be a numeric claim");
    let expires_at = claims["exp"]
        .as_i64()
        .expect("exp should be a numeric claim");

    assert_eq!(claims["iss"], issuer);
    assert_eq!(claims["aud"], "svc-a");
    assert_eq!(claims["nonce"], nonce);
    assert_eq!(claims["sub"], "user-alice");
    assert!(expires_at > now);
    assert!((now - issued_at).abs() <= 30);

    listener.stop().await;
}

impl LoopbackListener {
    async fn start() -> Self {
        let state = ListenerState::default();
        let records = state.records.clone();
        match StdTcpListener::bind("127.0.0.1:0") {
            Ok(std_listener) => {
                let addr = std_listener
                    .local_addr()
                    .expect("listener address should be available");
                std_listener
                    .set_nonblocking(true)
                    .expect("listener should become nonblocking");
                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("tokio listener should initialize");
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let app = Router::new()
                    .route("/callback", get(loopback_callback))
                    .with_state(state);
                let task = tokio::spawn(async move {
                    axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            let _ = shutdown_rx.await;
                        })
                        .await
                        .expect("loopback listener should serve requests");
                });

                Self {
                    addr,
                    records,
                    app: None,
                    shutdown: Some(shutdown_tx),
                    task: Some(task),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => Self {
                addr: "127.0.0.1:49152"
                    .parse()
                    .expect("fallback loopback address should parse"),
                records,
                app: Some(
                    Router::new()
                        .route("/callback", get(loopback_callback))
                        .with_state(state),
                ),
                shutdown: None,
                task: None,
            },
            Err(err) => panic!("loopback listener should bind: {err}"),
        }
    }

    fn redirect_uri(&self) -> String {
        format!("http://{}/callback", self.addr)
    }

    fn records(&self) -> Vec<CallbackRecord> {
        self.records
            .lock()
            .expect("loopback records lock should not be poisoned")
            .clone()
    }

    async fn dispatch(&self, redirect_url: &str) -> (StatusCode, String) {
        let prefix = format!("http://{}", self.addr);
        let path = redirect_url
            .strip_prefix(&prefix)
            .expect("redirect should target the loopback listener");

        if let Some(app) = &self.app {
            let response = request(
                app.clone(),
                Request::get(path)
                    .body(Body::empty())
                    .expect("loopback request should build"),
            )
            .await;
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("loopback response body should read");
            let text = String::from_utf8(body.to_vec()).expect("loopback body should be utf-8");
            return (status, text);
        }

        let mut stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("loopback listener should accept connections");
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.addr
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("request should write to loopback listener");

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("response should read from loopback listener");
        let body = response
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_string();
        let status = if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
        {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, body)
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

impl Drop for LoopbackListener {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl TempConfigDir {
    fn with_loopback_redirect(redirect_uri: &str) -> Self {
        let root = std::env::temp_dir().join(format!("pocket-oid-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("temp config directory should be created");
        copy_dir_all(&fixture_config_dir("config-basic"), &root);

        let clients_path = root.join("clients.json");
        let mut clients: Vec<Value> = serde_json::from_slice(
            &fs::read(&clients_path).expect("clients fixture should be readable"),
        )
        .expect("clients fixture should parse");
        let client = clients
            .first_mut()
            .and_then(Value::as_object_mut)
            .expect("config-basic should contain a client object");
        client.insert(
            "redirect_uris".to_string(),
            Value::Array(vec![Value::String(redirect_uri.to_string())]),
        );
        client.insert(
            "scopes".to_string(),
            Value::Array(vec![
                Value::String("default".to_string()),
                Value::String("openid".to_string()),
            ]),
        );
        client.insert(
            "response_types".to_string(),
            Value::Array(vec![Value::String("code".to_string())]),
        );
        fs::write(
            &clients_path,
            serde_json::to_vec_pretty(&clients).expect("clients fixture should serialize"),
        )
        .expect("temp clients fixture should write");

        Self { path: root }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempConfigDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn loopback_callback(
    State(state): State<ListenerState>,
    uri: Uri,
    Query(params): Query<HashMap<String, String>>,
) -> Html<&'static str> {
    state
        .records
        .lock()
        .expect("loopback records lock should not be poisoned")
        .push(CallbackRecord {
            path: uri.path().to_string(),
            query: uri.query().unwrap_or_default().to_string(),
            code: params.get("code").cloned(),
            state: params.get("state").cloned(),
            error: params.get("error").cloned(),
        });

    Html(
        "<!doctype html><html><body>Authentication successful, you can close this browser tab.</body></html>",
    )
}

fn build_authorize_path(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let mut params = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("scope", scope.to_string()),
    ];
    if let Some(state) = state {
        params.push(("state", state.to_string()));
    }
    if let Some(nonce) = nonce {
        params.push(("nonce", nonce.to_string()));
    }

    format!("/authorize?{}", query_string(&params))
}

fn query_string(params: &[(&str, String)]) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{key}={}", value.replace(' ', "%20")))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_body(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                encode_component(key, true),
                encode_component(value, true)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_component(value: &str, space_as_plus: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' if space_as_plus => encoded.push('+'),
            b' ' => encoded.push_str("%20"),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn session_cookie(response: &axum::http::Response<Body>) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie should be present")
        .split(';')
        .next()
        .expect("cookie should contain key value")
        .to_string()
}

fn query_value(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.to_string())
    })
}

fn path_from_url(url: &str) -> String {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    match without_scheme.find('/') {
        Some(index) => without_scheme[index..].to_string(),
        None => "/".to_string(),
    }
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("destination directory should be created");
    for entry in fs::read_dir(src).expect("fixture directory should be readable") {
        let entry = entry.expect("fixture entry should read");
        let source_path = entry.path();
        let destination_path = dst.join(entry.file_name());
        let metadata = entry.metadata().expect("fixture metadata should read");
        if metadata.is_dir() {
            copy_dir_all(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("fixture file should copy");
        }
    }
}
