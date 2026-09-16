mod views;

use crate::{
    admins::{AdminRecord, AdminStore, PasswordChangeResult},
    app::AppState,
    config::{ClientAuthMode, ClientConfig, ConsentMode, ReAuthConsent},
    error::AppError,
};
use axum::{
    Form, Router,
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const COOKIE: &str = "pocket_oid_admin";
const SESSION_TTL: Duration = Duration::from_secs(3600);

/// Only fields safe to render. Client secrets and arbitrary metadata never enter views.
#[derive(Clone)]
pub struct ClientSummary {
    pub id: String,
    pub enabled: bool,
    pub mode: &'static str,
    pub scopes: Vec<String>,
    pub audience: Option<String>,
    pub redirects: Vec<String>,
    pub pkce: bool,
    pub consent: &'static str,
    pub trusted: Option<String>,
    pub upstream_scopes: Vec<String>,
    pub algorithm: Option<String>,
    pub lifetime: Option<u64>,
}

impl From<&ClientConfig> for ClientSummary {
    fn from(c: &ClientConfig) -> Self {
        let upstream = c.auth_mode == ClientAuthMode::ReAuth;
        Self {
            id: c.client_id.clone(),
            enabled: c.enabled,
            mode: if upstream { "Upstream" } else { "Local" },
            scopes: c.scopes.clone(),
            audience: c.audience.clone(),
            redirects: c.redirect_uris.clone(),
            pkce: c.require_pkce,
            consent: if upstream {
                match c.re_auth.as_ref().map(|r| r.consent) {
                    Some(ReAuthConsent::Skip) => "Skip local consent",
                    _ => "Show local consent",
                }
            } else if c.consent_mode == ConsentMode::Skip {
                "Skip consent"
            } else {
                "Always show consent"
            },
            trusted: if upstream {
                c.re_auth.as_ref().map(|r| r.provider_id.clone())
            } else {
                None
            },
            upstream_scopes: if upstream {
                c.re_auth
                    .as_ref()
                    .map(|r| r.upstream_scopes.clone())
                    .unwrap_or_default()
            } else {
                vec![]
            },
            algorithm: c.signing_algorithm.map(|a| a.as_str().to_string()),
            lifetime: c.token_ttl_seconds,
        }
    }
}

#[derive(Clone)]
struct Session {
    csrf: String,
    admin_id: Option<String>,
    credential_version: Option<i64>,
    expires: Instant,
}

pub struct AdminConsole {
    store: Option<Arc<AdminStore>>,
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<VecDeque<Instant>>,
    verification: Arc<Semaphore>,
    pub clients: Vec<ClientSummary>,
}

impl AdminConsole {
    pub fn load(root: &Path, clients: &[ClientConfig]) -> Result<Self, AppError> {
        let store = if root.join("admins.json").try_exists()? {
            Some(Arc::new(AdminStore::load_from_directory(root).map_err(
                |e| AppError::Config(format!("administrator store: {e:#}")),
            )?))
        } else {
            None
        };
        Ok(Self {
            store,
            sessions: Mutex::new(HashMap::new()),
            attempts: Mutex::new(VecDeque::new()),
            verification: Arc::new(Semaphore::new(2)),
            clients: clients.iter().map(ClientSummary::from).collect(),
        })
    }

    fn session(&self, headers: &HeaderMap) -> Option<Session> {
        let token = cookie(headers)?;
        let mut sessions = self.sessions.lock().ok()?;
        sessions.retain(|_, s| s.expires > Instant::now());
        sessions.get(token).cloned()
    }

    fn new_session(&self, admin: Option<&AdminRecord>) -> anyhow::Result<(String, String)> {
        let token = random_token()?;
        let csrf = random_token()?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session lock unavailable"))?;
        sessions.retain(|_, s| s.expires > Instant::now());
        anyhow::ensure!(
            sessions.len() < 4096,
            "administrator session capacity reached"
        );
        let ttl = if admin.is_some() {
            SESSION_TTL
        } else {
            Duration::from_secs(600)
        };
        sessions.insert(
            token.clone(),
            Session {
                csrf: csrf.clone(),
                admin_id: admin.map(|admin| admin.id.clone()),
                credential_version: admin.map(|admin| admin.credential_version),
                expires: Instant::now() + ttl,
            },
        );
        Ok((token, csrf))
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(|| async { Redirect::to("/admin/clients") }))
        .route("/admin/", get(|| async { Redirect::to("/admin/clients") }))
        .route("/admin/login", get(login_page).post(login))
        .route("/admin/logout", post(logout))
        .route(
            "/admin/account/password",
            get(password_page).post(change_password),
        )
        .route("/admin/clients", get(clients))
        .route("/admin/users", get(users))
        .route("/admin/provider", get(provider))
        .route("/admin/login-preview", get(login_preview))
        .route("/admin/assets/:name", get(asset))
        .layer(axum::middleware::map_response(protect_response))
}

async fn protect_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; frame-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'none'; object-src 'none'"));
    response
}

fn random_token() -> anyhow::Result<String> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("random number generation failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| {
            let (name, value) = p.trim().split_once('=')?;
            (name == COOKIE).then_some(value)
        })
}

fn with_cookie(mut response: Response, token: &str, state: &AppState, clear: bool) -> Response {
    let secure = if state.provider.issuer.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let value = format!(
        "{COOKIE}={token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age={}{}",
        if clear { 0 } else { SESSION_TTL.as_secs() },
        secure
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

fn error_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Administrator console temporarily unavailable.",
    )
        .into_response()
}

enum AccessError {
    SignIn,
    Unavailable,
}

impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        match self {
            Self::SignIn => Redirect::to("/admin/login").into_response(),
            Self::Unavailable => error_response(),
        }
    }
}

async fn authorized(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(AdminRecord, Session), AccessError> {
    let session = state
        .admin_console
        .session(headers)
        .ok_or(AccessError::SignIn)?;
    let id = session.admin_id.clone().ok_or(AccessError::SignIn)?;
    let store = state
        .admin_console
        .store
        .clone()
        .ok_or(AccessError::Unavailable)?;
    match tokio::task::spawn_blocking(move || store.enabled_admin(&id)).await {
        Ok(Ok(Some(admin))) if session.credential_version == Some(admin.credential_version) => {
            Ok((admin, session))
        }
        Ok(Ok(Some(_))) => Err(AccessError::SignIn),
        Ok(Ok(None)) => Err(AccessError::SignIn),
        _ => Err(AccessError::Unavailable),
    }
}

#[derive(Default, Deserialize)]
struct LoginQuery {
    password_changed: Option<String>,
}

async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    if authorized(&state, &headers).await.is_ok() {
        return Redirect::to("/admin/clients").into_response();
    }
    if state.admin_console.store.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE, Html(views::login(String::new(), Some("Administrator access is not configured. Configure admins.json and create an administrator with the CLI.".into()), false))).into_response();
    }
    // Reuse the browser's pre-auth session so multiple tabs do not invalidate each other.
    if let Some(session) = state
        .admin_console
        .session(&headers)
        .filter(|s| s.admin_id.is_none())
    {
        return Html(views::login(
            session.csrf,
            None,
            query.password_changed.is_some(),
        ))
        .into_response();
    }
    match state.admin_console.new_session(None) {
        Ok((token, csrf)) => with_cookie(
            Html(views::login(csrf, None, query.password_changed.is_some())).into_response(),
            &token,
            &state,
            false,
        ),
        Err(_) => error_response(),
    }
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    csrf: String,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let password = Zeroizing::new(form.password);
    let Some(session) = state
        .admin_console
        .session(&headers)
        .filter(|s| s.admin_id.is_none() && csrf_matches(&s.csrf, &form.csrf))
    else {
        return (
            StatusCode::FORBIDDEN,
            Html(views::login(
                String::new(),
                Some("This sign-in form expired. Reload the page and try again.".into()),
                false,
            )),
        )
            .into_response();
    };
    let allowed = {
        let Ok(mut attempts) = state.admin_console.attempts.lock() else {
            return error_response();
        };
        attempts.retain(|at| at.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 30 {
            false
        } else {
            attempts.push_back(Instant::now());
            true
        }
    };
    let Ok(permit) = state.admin_console.verification.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(views::login(
                session.csrf,
                Some("Please wait a moment before trying again.".into()),
                false,
            )),
        )
            .into_response();
    };
    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(views::login(
                session.csrf,
                Some("Too many sign-in attempts. Try again in a minute.".into()),
                false,
            )),
        )
            .into_response();
    }
    let Some(store) = state.admin_console.store.clone() else {
        return error_response();
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.authenticate(&form.username, &password)
    })
    .await;
    match result {
        Ok(Ok(Some(admin))) => {
            let Ok((token, _)) = state.admin_console.new_session(Some(&admin)) else {
                return error_response();
            };
            if let Some(old) = cookie(&headers)
                && let Ok(mut sessions) = state.admin_console.sessions.lock()
            {
                sessions.remove(old);
            }
            with_cookie(
                Redirect::to("/admin/clients").into_response(),
                &token,
                &state,
                false,
            )
        }
        Ok(Ok(None)) => (
            StatusCode::UNAUTHORIZED,
            Html(views::login(
                session.csrf,
                Some("Invalid administrator username or password.".into()),
                false,
            )),
        )
            .into_response(),
        _ => error_response(),
    }
}

#[derive(Deserialize)]
struct PasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
    csrf: String,
}

async fn password_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (admin, session) = match authorized(&state, &headers).await {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    Html(views::password(admin.username, session.csrf, None)).into_response()
}

fn password_form_response(
    status: StatusCode,
    admin: &AdminRecord,
    session: &Session,
    message: &str,
) -> Response {
    (
        status,
        Html(views::password(
            admin.username.clone(),
            session.csrf.clone(),
            Some(message.into()),
        )),
    )
        .into_response()
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let current_password = Zeroizing::new(form.current_password);
    let new_password = Zeroizing::new(form.new_password);
    let confirm_password = Zeroizing::new(form.confirm_password);
    let (admin, session) = match authorized(&state, &headers).await {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return password_form_response(
            StatusCode::FORBIDDEN,
            &admin,
            &session,
            "This form expired. Reload the page and try again.",
        );
    }
    let validation_error = if current_password.is_empty() {
        Some("Enter your current password.")
    } else if new_password.is_empty() {
        Some("Enter a new password.")
    } else if confirm_password.is_empty() {
        Some("Confirm your new password.")
    } else if new_password.as_str() != confirm_password.as_str() {
        Some("New passwords do not match.")
    } else {
        None
    };
    if let Some(message) = validation_error {
        return password_form_response(StatusCode::UNPROCESSABLE_ENTITY, &admin, &session, message);
    }

    let allowed = {
        let Ok(mut attempts) = state.admin_console.attempts.lock() else {
            return error_response();
        };
        attempts.retain(|at| at.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 30 {
            false
        } else {
            attempts.push_back(Instant::now());
            true
        }
    };
    if !allowed {
        return password_form_response(
            StatusCode::TOO_MANY_REQUESTS,
            &admin,
            &session,
            "Too many password attempts. Try again in a minute.",
        );
    }
    let Ok(permit) = state.admin_console.verification.clone().try_acquire_owned() else {
        return password_form_response(
            StatusCode::TOO_MANY_REQUESTS,
            &admin,
            &session,
            "Please wait a moment before trying again.",
        );
    };
    let Some(store) = state.admin_console.store.clone() else {
        return error_response();
    };
    let admin_id = admin.id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.change_password(&admin_id, &current_password, &new_password)
    })
    .await;
    match result {
        Ok(Ok(PasswordChangeResult::Changed)) => {
            if let Ok(mut sessions) = state.admin_console.sessions.lock() {
                sessions.retain(|_, candidate| candidate.admin_id.as_deref() != Some(&admin.id));
            }
            with_cookie(
                Redirect::to("/admin/login?password_changed=1").into_response(),
                "",
                &state,
                true,
            )
        }
        Ok(Ok(PasswordChangeResult::IncorrectCurrentPassword)) => password_form_response(
            StatusCode::UNAUTHORIZED,
            &admin,
            &session,
            "Current password is incorrect.",
        ),
        Ok(Ok(PasswordChangeResult::PasswordUnchanged)) => password_form_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &admin,
            &session,
            "New password must be different from your current password.",
        ),
        Ok(Ok(PasswordChangeResult::CredentialsChanged)) => password_form_response(
            StatusCode::CONFLICT,
            &admin,
            &session,
            "Your credentials changed in another request. Sign in again and retry.",
        ),
        Ok(Ok(PasswordChangeResult::AccountUnavailable)) => with_cookie(
            Redirect::to("/admin/login").into_response(),
            "",
            &state,
            true,
        ),
        _ => password_form_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &admin,
            &session,
            "Could not change your password. Try again.",
        ),
    }
}

fn csrf_matches(expected: &str, actual: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf: String,
}
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let Some(session) = state.admin_console.session(&headers) else {
        return Redirect::to("/admin/login").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(token) = cookie(&headers)
        && let Ok(mut sessions) = state.admin_console.sessions.lock()
    {
        sessions.remove(token);
    }
    with_cookie(
        Redirect::to("/admin/login").into_response(),
        "",
        &state,
        true,
    )
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Selection {
    pub q: String,
    pub id: Option<String>,
    pub status: String,
    pub auth: String,
    pub sort: String,
}

impl Selection {
    fn status(&self) -> &str {
        match self.status.as_str() {
            "enabled" => "enabled",
            "disabled" => "disabled",
            _ => "all",
        }
    }

    fn auth(&self) -> &str {
        match self.auth.as_str() {
            "local" => "local",
            "upstream" => "upstream",
            _ => "all",
        }
    }

    fn sort(&self) -> &str {
        if self.sort == "desc" { "desc" } else { "asc" }
    }

    fn matches(&self, text: &str, enabled: bool) -> bool {
        text.to_lowercase().contains(&self.q.trim().to_lowercase())
            && match self.status() {
                "enabled" => enabled,
                "disabled" => !enabled,
                _ => true,
            }
    }

    fn matches_client(&self, client: &ClientSummary) -> bool {
        self.matches(
            &format!("{} {}", client.id, client.scopes.join(" ")),
            client.enabled,
        ) && (self.auth() == "all" || self.auth().eq_ignore_ascii_case(client.mode))
    }

    fn matches_user(&self, user: &crate::users::UserSummary) -> bool {
        self.matches(&format!("{} {}", user.username, user.id), user.enabled)
    }

    fn url(&self, section: &str, id: Option<&str>) -> String {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        if let Some(id) = id {
            params.append_pair("id", id);
        }
        if !self.q.is_empty() {
            params.append_pair("q", &self.q);
        }
        if self.status() != "all" {
            params.append_pair("status", self.status());
        }
        if section == "clients" && self.auth() != "all" {
            params.append_pair("auth", self.auth());
        }
        if self.sort() != "asc" {
            params.append_pair("sort", self.sort());
        }
        let params = params.finish();
        if params.is_empty() {
            format!("/admin/{section}")
        } else {
            format!("/admin/{section}?{params}")
        }
    }
}

async fn clients(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(selection): Query<Selection>,
) -> Response {
    let (admin, session) = match authorized(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r.into_response(),
    };
    let status = if selection
        .id
        .as_ref()
        .is_some_and(|id| !state.admin_console.clients.iter().any(|c| &c.id == id))
    {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::OK
    };
    (
        status,
        Html(views::clients(
            admin.username,
            session.csrf,
            &state.admin_console.clients,
            &state.provider,
            selection,
        )),
    )
        .into_response()
}

async fn users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(selection): Query<Selection>,
) -> Response {
    let (admin, session) = match authorized(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r.into_response(),
    };
    let source = state.users.source_name();
    let store = state.users.clone();
    let records = tokio::task::spawn_blocking(move || store.list()).await;
    let records = records.ok().and_then(Result::ok);
    // An inspector must never describe a user excluded by the visible list.
    // Redirect also clears stale selections for direct GETs without JavaScript.
    if let Some(selected) = records.as_ref().and_then(|users| {
        users
            .iter()
            .find(|user| Some(&user.id) == selection.id.as_ref())
    }) && !selection.matches_user(selected)
    {
        return Redirect::to(&selection.url("users", None)).into_response();
    }
    let status = if records.is_none() {
        StatusCode::SERVICE_UNAVAILABLE
    } else if selection
        .id
        .as_ref()
        .is_some_and(|id| !records.as_ref().unwrap().iter().any(|u| &u.id == id))
    {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::OK
    };
    (
        status,
        Html(views::users(
            admin.username,
            session.csrf,
            records,
            source,
            selection,
        )),
    )
        .into_response()
}

async fn provider(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (admin, session) = match authorized(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r.into_response(),
    };
    Html(views::provider(
        admin.username,
        session.csrf,
        &state.provider,
        &state.discovery,
    ))
    .into_response()
}

async fn login_preview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorized(&state, &headers).await {
        return response.into_response();
    }
    Html(crate::frontend::login_page(
        &state.provider.name,
        "",
        None,
        state.provider.login_background_color.as_deref(),
    ))
    .into_response()
}

async fn asset(UrlPath(name): UrlPath<String>) -> Response {
    let (kind, data): (&str, &[u8]) = match name.as_str() {
        "console.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../../assets/admin/console.css"),
        ),
        "console.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../../assets/admin/console.js"),
        ),
        "logo.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/pocket-oid-logo.svg"),
        ),
        "inter-400.woff2" => (
            "font/woff2",
            include_bytes!("../../assets/admin/inter-400.woff2"),
        ),
        "inter-500.woff2" => (
            "font/woff2",
            include_bytes!("../../assets/admin/inter-500.woff2"),
        ),
        "inter-600.woff2" => (
            "font/woff2",
            include_bytes!("../../assets/admin/inter-600.woff2"),
        ),
        "inter-700.woff2" => (
            "font/woff2",
            include_bytes!("../../assets/admin/inter-700.woff2"),
        ),
        "clients.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/clients.svg"),
        ),
        "users.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/users.svg"),
        ),
        "provider.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/provider.svg"),
        ),
        "search.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/search.svg"),
        ),
        "close.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/close.svg"),
        ),
        "chevron.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/chevron.svg"),
        ),
        "enabled.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/enabled.svg"),
        ),
        "disabled.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/disabled.svg"),
        ),
        "menu.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/menu.svg"),
        ),
        "logout.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/logout.svg"),
        ),
        "password.svg" => (
            "image/svg+xml",
            include_bytes!("../../assets/admin/password.svg"),
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, kind)], data).into_response()
}
