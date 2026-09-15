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
    AdminStore::load_from_directory(&config.path)
        .unwrap()
        .create("auditor", "auditor-admin-password")
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

async fn sign_in_as(app: &Router, username: &str, password: &str) -> String {
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
            "username={username}&password={password}&csrf={}",
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

async fn sign_in(app: &Router) -> String {
    sign_in_as(app, "operator", "test-admin-password").await
}

fn password_form(csrf: &str, current: &str, new: &str, confirm: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf", csrf)
        .append_pair("current_password", current)
        .append_pair("new_password", new)
        .append_pair("confirm_password", confirm)
        .finish()
}

#[tokio::test]
async fn console_requires_a_separate_administrator_session() {
    let (_config, app) = setup();
    for path in [
        "/admin/clients",
        "/admin/users",
        "/admin/provider",
        "/admin/login-preview",
        "/admin/account/password",
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
async fn provider_connection_details_match_public_discovery_and_copy_complete_urls() {
    let (config, _) = setup();
    for issuer in [
        "https://id.example.com",
        "https://id.example.com/",
        "https://id.example.com/tenant/pocket-oid",
        "https://id.example.com/tenant/pocket-oid/",
    ] {
        let path = config.path.join("provider.json");
        let mut provider: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        provider["issuer"] = json!(issuer);
        fs::write(path, serde_json::to_vec(&provider).unwrap()).unwrap();
        let app = AppState::initialize(&config.path).unwrap().router();
        let (status, headers, anonymous) = get(&app, "/admin/provider", "").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(headers["location"], "/admin/login");
        assert!(!anonymous.contains("OIDC connection details"));

        let (status, _, metadata) = get(&app, "/.well-known/openid-configuration", "").await;
        assert_eq!(status, StatusCode::OK);
        let metadata: Value = serde_json::from_str(&metadata).unwrap();
        let cookie = sign_in(&app).await;
        let (status, _, page) = get(&app, "/admin/provider", &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("OIDC connection details"));
        assert!(page.contains("Use the issuer or discovery URL when configuring an OIDC client."));
        let base = issuer.trim_end_matches('/');
        for (label, expected) in [
            (
                "Discovery URL",
                format!("{base}/.well-known/openid-configuration"),
            ),
            (
                "Authorization endpoint",
                metadata["authorization_endpoint"].as_str().unwrap().into(),
            ),
            (
                "Token endpoint",
                metadata["token_endpoint"].as_str().unwrap().into(),
            ),
            ("JWKS URL", metadata["jwks_uri"].as_str().unwrap().into()),
        ] {
            assert!(expected.starts_with(&format!("{base}/")));
            assert!(page.contains(&format!(
                "<dt>{label}</dt><dd class=\"mono\">{expected}</dd>"
            )));
            assert!(page.contains(&format!(
                "data-copy=\"{expected}\" aria-label=\"Copy {label}\""
            )));
        }
        assert_eq!(page.matches("<dt>Issuer URL</dt>").count(), 1);
        assert!(page.contains(&format!(
            "data-copy=\"{issuer}\" aria-label=\"Copy Issuer URL\""
        )));
    }
}

#[tokio::test]
async fn changes_own_password_and_invalidates_only_that_administrators_sessions() {
    let (_config, app) = setup();
    let first = sign_in(&app).await;
    let second = sign_in(&app).await;
    let auditor = sign_in_as(&app, "auditor", "auditor-admin-password").await;
    let (status, _, body) = get(&app, "/admin/account/password", &first).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Change password"));
    assert!(body.contains("href=\"/admin/account/password\""));
    assert!(body.contains("autocomplete=\"current-password\""));
    assert_eq!(body.matches("autocomplete=\"new-password\"").count(), 2);
    assert!(!body.contains("value=\"test-admin-password\""));

    let (status, headers, body) = post(
        &app,
        "/admin/account/password",
        &first,
        &password_form(
            &csrf(&body),
            "test-admin-password",
            "new-admin-password",
            "new-admin-password",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/admin/login?password_changed=1");
    assert!(
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert!(body.is_empty());

    for invalidated in [&first, &second] {
        assert_eq!(
            get(&app, "/admin/clients", invalidated).await.0,
            StatusCode::SEE_OTHER
        );
    }
    assert_eq!(
        get(&app, "/admin/clients", &auditor).await.0,
        StatusCode::OK
    );
    assert_eq!(
        sign_in_attempt(&app, "operator", "test-admin-password").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sign_in_attempt(&app, "operator", "new-admin-password").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        sign_in_attempt(&app, "auditor", "auditor-admin-password").await,
        StatusCode::SEE_OTHER
    );

    let (_, _, success) = get(&app, "/admin/login?password_changed=1", "").await;
    assert!(success.contains("Your password was changed"));
}

async fn sign_in_attempt(app: &Router, username: &str, password: &str) -> StatusCode {
    let (_, headers, body) = get(app, "/admin/login", "").await;
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    post(
        app,
        "/admin/login",
        cookie,
        &url::form_urlencoded::Serializer::new(String::new())
            .append_pair("username", username)
            .append_pair("password", password)
            .append_pair("csrf", &csrf(&body))
            .finish(),
    )
    .await
    .0
}

#[tokio::test]
async fn password_validation_failures_preserve_password_and_session() {
    let (_config, app) = setup();
    let cookie = sign_in(&app).await;
    let (_, _, page) = get(&app, "/admin/account/password", &cookie).await;
    let token = csrf(&page);

    let (status, _, body) = post(
        &app,
        "/admin/account/password",
        &cookie,
        &password_form(&token, "", "replacement", "replacement"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("Enter your current password."));
    assert_eq!(get(&app, "/admin/clients", &cookie).await.0, StatusCode::OK);

    let (status, _, body) = post(
        &app,
        "/admin/account/password",
        &cookie,
        &password_form(&token, "wrong-password", "replacement", "replacement"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("Current password is incorrect."));
    assert!(!body.contains("wrong-password") && !body.contains("replacement"));
    assert_eq!(get(&app, "/admin/clients", &cookie).await.0, StatusCode::OK);

    let (status, _, body) = post(
        &app,
        "/admin/account/password",
        &cookie,
        &password_form(&token, "test-admin-password", "replacement", "different"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("New passwords do not match."));
    assert!(!body.contains("replacement") && !body.contains("different"));
    assert_eq!(get(&app, "/admin/clients", &cookie).await.0, StatusCode::OK);

    let (status, _, body) = post(
        &app,
        "/admin/account/password",
        &cookie,
        &password_form(
            &token,
            "test-admin-password",
            "test-admin-password",
            "test-admin-password",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.contains("New password must be different"));
    assert_eq!(get(&app, "/admin/clients", &cookie).await.0, StatusCode::OK);
    assert_eq!(
        sign_in_attempt(&app, "operator", "test-admin-password").await,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn password_change_requires_authentication_csrf_and_enabled_account() {
    let (config, app) = setup();
    let anonymous = post(
        &app,
        "/admin/account/password",
        "",
        &password_form("anything", "old", "new", "new"),
    )
    .await;
    assert_eq!(anonymous.0, StatusCode::SEE_OTHER);
    assert_eq!(anonymous.1["location"], "/admin/login");

    let cookie = sign_in(&app).await;
    let (status, _, body) = post(
        &app,
        "/admin/account/password",
        &cookie,
        &password_form("wrong", "test-admin-password", "replacement", "replacement"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("This form expired."));
    assert_eq!(get(&app, "/admin/clients", &cookie).await.0, StatusCode::OK);

    rusqlite::Connection::open(config.path.join("data/admins.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE admins SET enabled = 0 WHERE username = 'operator'",
            [],
        )
        .unwrap();
    let disabled = post(
        &app,
        "/admin/account/password",
        &cookie,
        &password_form("wrong", "test-admin-password", "replacement", "replacement"),
    )
    .await;
    assert_eq!(disabled.0, StatusCode::SEE_OTHER);
    assert_eq!(disabled.1["location"], "/admin/login");
}

#[tokio::test]
async fn password_database_failure_has_no_false_success_and_preserves_access() {
    let (config, app) = setup();
    let cookie = sign_in(&app).await;
    let (_, _, page) = get(&app, "/admin/account/password", &cookie).await;
    rusqlite::Connection::open(config.path.join("data/admins.sqlite3"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_password_change
             BEFORE UPDATE OF password_hash ON admins
             BEGIN SELECT RAISE(FAIL, 'simulated write failure'); END;",
        )
        .unwrap();

    let (status, headers, body) = post(
        &app,
        "/admin/account/password",
        &cookie,
        &password_form(
            &csrf(&page),
            "test-admin-password",
            "replacement-password",
            "replacement-password",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!headers.contains_key("location"));
    assert!(body.contains("Could not change your password. Try again."));
    assert!(!body.contains("Your password was changed"));
    assert_eq!(get(&app, "/admin/clients", &cookie).await.0, StatusCode::OK);
    assert_eq!(
        sign_in_attempt(&app, "operator", "test-admin-password").await,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn concurrent_old_password_login_cannot_preserve_access_after_change() {
    let (_config, app) = setup();
    let changer = sign_in(&app).await;
    let (_, _, change_page) = get(&app, "/admin/account/password", &changer).await;
    let (_, login_headers, login_page) = get(&app, "/admin/login", "").await;
    let login_cookie = login_headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let change_form = password_form(
        &csrf(&change_page),
        "test-admin-password",
        "new-admin-password",
        "new-admin-password",
    );
    let login_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("username", "operator")
        .append_pair("password", "test-admin-password")
        .append_pair("csrf", &csrf(&login_page))
        .finish();

    let (change, login) = tokio::join!(
        post(&app, "/admin/account/password", &changer, &change_form),
        post(&app, "/admin/login", &login_cookie, &login_form),
    );
    assert_eq!(change.0, StatusCode::SEE_OTHER);
    assert!(matches!(
        login.0,
        StatusCode::SEE_OTHER | StatusCode::UNAUTHORIZED
    ));
    if login.0 == StatusCode::SEE_OTHER {
        let stale_cookie = login.1["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_eq!(
            get(&app, "/admin/clients", stale_cookie).await.0,
            StatusCode::SEE_OTHER
        );
    }
    assert_eq!(
        sign_in_attempt(&app, "operator", "new-admin-password").await,
        StatusCode::SEE_OTHER
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
        "menu", "logout", "password",
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
