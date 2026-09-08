use crate::common::SigningTestConfig;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use pocket_oid::{admins::AdminStore, app::AppState, config::SigningAlgorithm};
use serde_json::{Value, json};
use std::fs;
use tower::ServiceExt;

fn setup() -> (SigningTestConfig, Router) {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    fs::write(
        config.path.join("admins.json"),
        r#"{"provider":"sqlite","path":"data/admins.sqlite3"}"#,
    )
    .unwrap();
    AdminStore::load_from_directory(&config.path)
        .unwrap()
        .create("operator", "test-admin-password")
        .unwrap();
    let mut clients: Vec<Value> =
        serde_json::from_slice(&fs::read(config.path.join("clients.json")).unwrap()).unwrap();
    clients.push(json!({"client_id":"disabled-client", "client_secret":"never-render-this-client-secret", "enabled":false,
        "scopes":["reports:read"], "signing_algorithm":"ES256", "token_ttl_seconds":900}));
    clients.push(json!({"client_id":"<script>unsafe</script>", "client_secret":"another-secret", "enabled":false}));
    fs::write(
        config.path.join("clients.json"),
        serde_json::to_vec(&clients).unwrap(),
    )
    .unwrap();
    let app = AppState::initialize(&config.path).unwrap().router();
    (config, app)
}

async fn get(
    app: &Router,
    path: &str,
    cookie: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app
        .clone()
        .oneshot(
            Request::get(path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 2_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, headers, body)
}

async fn post(
    app: &Router,
    path: &str,
    cookie: &str,
    form: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("cookie", cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 2_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, headers, body)
}

fn csrf(body: &str) -> String {
    body.split("name=\"csrf\" value=\"")
        .nth(1)
        .expect("CSRF input")
        .split('"')
        .next()
        .unwrap()
        .into()
}

async fn sign_in(app: &Router) -> String {
    let (status, headers, body) = get(app, "/admin/login", "").await;
    assert_eq!(status, StatusCode::OK);
    let initial = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (status, headers, _) = post(
        app,
        "/admin/login",
        initial,
        &format!(
            "username=operator&password=test-admin-password&csrf={}",
            csrf(&body)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = headers["set-cookie"].to_str().unwrap();
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("SameSite=Strict")
            && cookie.contains("Secure")
    );
    assert_ne!(initial, cookie.split(';').next().unwrap());
    cookie.split(';').next().unwrap().into()
}

#[tokio::test]
async fn console_requires_a_separate_administrator_session() {
    let (_config, app) = setup();
    for path in [
        "/admin/clients",
        "/admin/users",
        "/admin/provider",
        "/admin/login-preview",
    ] {
        let (status, headers, body) = get(&app, path, "pocket_oid_session=ordinary-session").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(headers["location"], "/admin/login");
        assert!(!body.contains("disabled-client"));
    }
    let (_, headers, body) = get(&app, "/admin/login", "").await;
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert_eq!(
        post(
            &app,
            "/admin/login",
            cookie,
            "username=operator&password=test-admin-password&csrf=wrong"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // The existing ordinary user's valid credentials cannot sign into the console.
    let result = post(
        &app,
        "/admin/login",
        cookie,
        &format!("username=alice&password=password123&csrf={}", csrf(&body)),
    )
    .await;
    assert_eq!(result.0, StatusCode::UNAUTHORIZED);
    assert!(
        result
            .2
            .contains("Invalid administrator username or password")
    );
}

#[tokio::test]
async fn lists_disabled_clients_escapes_html_and_never_renders_credentials() {
    let (_config, app) = setup();
    let cookie = sign_in(&app).await;
    let (status, headers, body) = get(&app, "/admin/clients", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert!(headers.contains_key("content-security-policy"));
    assert!(body.contains("disabled-client") && body.contains("Disabled"));
    assert!(body.contains("&lt;script&gt;unsafe&lt;/script&gt;"));
    assert!(!body.contains("<script>unsafe</script>"));
    assert!(!body.contains("never-render-this-client-secret"));
    let (_, _, detail) = get(&app, "/admin/clients?id=disabled-client", &cookie).await;
    assert!(detail.contains("ES256") && detail.contains("Client override"));
    assert!(detail.contains("900 seconds (15 minutes)"));
    assert!(!detail.contains("never-render-this-client-secret"));
    assert_eq!(
        get(&app, "/admin/clients?id=missing", &cookie).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, _, users) = get(&app, "/admin/users", &cookie).await;
    assert!(users.contains("JSON") && users.contains("user-alice"));
    assert!(!users.contains("$argon2id$") && !users.contains("password123"));
    let (_, _, provider) = get(&app, "/admin/provider", &cookie).await;
    assert!(provider.contains("Default background") && provider.contains("3,600 seconds (1 hour)"));
}

#[tokio::test]
async fn logout_checks_csrf_and_invalidates_the_session() {
    let (_config, app) = setup();
    let cookie = sign_in(&app).await;
    let (_, _, body) = get(&app, "/admin/clients", &cookie).await;
    assert_eq!(
        post(&app, "/admin/logout", &cookie, "csrf=wrong").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(get(&app, "/admin/clients", &cookie).await.0, StatusCode::OK);
    let (status, headers, _) = post(
        &app,
        "/admin/logout",
        &cookie,
        &format!("csrf={}", csrf(&body)),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        get(&app, "/admin/clients", &cookie).await.0,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn disabled_administrators_lose_existing_console_access() {
    let (config, app) = setup();
    let cookie = sign_in(&app).await;
    rusqlite::Connection::open(config.path.join("data/admins.sqlite3"))
        .unwrap()
        .execute("UPDATE admins SET enabled = 0", [])
        .unwrap();
    assert_eq!(
        get(&app, "/admin/users", &cookie).await.0,
        StatusCode::SEE_OTHER
    );
    let (_, headers, body) = get(&app, "/admin/login", "").await;
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert_eq!(
        post(
            &app,
            "/admin/login",
            cookie,
            &format!(
                "username=operator&password=test-admin-password&csrf={}",
                csrf(&body)
            )
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn console_is_unavailable_without_admin_configuration_but_provider_runs() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    let app = AppState::initialize(&config.path).unwrap().router();
    assert_eq!(get(&app, "/healthz", "").await.0, StatusCode::OK);
    assert_eq!(
        get(&app, "/admin/login", "").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn sqlite_directory_observes_updates_and_reports_read_failures() {
    let (config, _) = setup();
    let users: Value =
        serde_json::from_slice(&fs::read(config.path.join("users.json")).unwrap()).unwrap();
    let hash = users["users"][0]["password_hash"].as_str().unwrap();
    let db = rusqlite::Connection::open(config.path.join("data/users.sqlite3")).unwrap();
    db.execute_batch(
        "CREATE TABLE users (
        id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        PRAGMA user_version = 1;",
    )
    .unwrap();
    db.execute(
        "INSERT INTO users (id, username, password_hash) VALUES ('local-1', 'local-user', ?1)",
        [hash],
    )
    .unwrap();
    fs::write(
        config.path.join("users.json"),
        r#"{"provider":"sqlite","path":"data/users.sqlite3"}"#,
    )
    .unwrap();
    let app = AppState::initialize(&config.path).unwrap().router();
    let cookie = sign_in(&app).await;
    let (_, _, body) = get(&app, "/admin/users?id=local-1", &cookie).await;
    assert!(body.contains("local-user") && body.contains("SQLite"));
    assert!(!body.contains(hash));
    db.execute("UPDATE users SET enabled = 0", []).unwrap();
    let (status, _, body) = get(&app, "/admin/users?id=local-1", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Disabled"));
    assert_eq!(
        get(&app, "/admin/users?id=missing", &cookie).await.0,
        StatusCode::NOT_FOUND
    );
    db.execute("DROP TABLE users", []).unwrap();
    let (status, _, body) = get(&app, "/admin/users", &cookie).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("Could not load users.") && body.contains("Retry"));
}

#[tokio::test]
async fn embedded_icons_are_valid_standalone_svg_documents() {
    let config = SigningTestConfig::new(SigningAlgorithm::RS256);
    let app = AppState::initialize(&config.path).unwrap().router();
    for name in [
        "clients", "users", "provider", "search", "close", "chevron", "enabled", "disabled",
        "menu", "logout",
    ] {
        let (status, headers, body) = get(&app, &format!("/admin/assets/{name}.svg"), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "image/svg+xml");
        assert_eq!(
            body.matches("xmlns=").count(),
            1,
            "{name} must have exactly one namespace"
        );
        assert!(body.starts_with("<svg ") && body.trim_end().ends_with("</svg>"));
    }
    assert_eq!(
        get(&app, "/admin/assets/unknown", "").await.0,
        StatusCode::NOT_FOUND
    );
}
