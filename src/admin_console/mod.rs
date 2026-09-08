mod views;

use crate::{
    admins::{AdminRecord, AdminStore},
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

    fn new_session(&self, admin_id: Option<String>) -> anyhow::Result<(String, String)> {
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
        let ttl = if admin_id.is_some() {
            SESSION_TTL
        } else {
            Duration::from_secs(600)
        };
        sessions.insert(
            token.clone(),
            Session {
                csrf: csrf.clone(),
                admin_id,
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
        Ok(Ok(Some(admin))) => Ok((admin, session)),
        Ok(Ok(None)) => Err(AccessError::SignIn),
        _ => Err(AccessError::Unavailable),
    }
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorized(&state, &headers).await.is_ok() {
        return Redirect::to("/admin/clients").into_response();
    }
    if state.admin_console.store.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE, Html(views::login(String::new(), Some("Administrator access is not configured. Configure admins.json and create an administrator with the CLI.".into())))).into_response();
    }
    // Reuse the browser's pre-auth session so multiple tabs do not invalidate each other.
    if let Some(session) = state
        .admin_console
        .session(&headers)
        .filter(|s| s.admin_id.is_none())
    {
        return Html(views::login(session.csrf, None)).into_response();
    }
    match state.admin_console.new_session(None) {
        Ok((token, csrf)) => with_cookie(
            Html(views::login(csrf, None)).into_response(),
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
            let Ok((token, _)) = state.admin_console.new_session(Some(admin.id)) else {
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
            )),
        )
            .into_response(),
        _ => error_response(),
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

#[derive(Default, Deserialize)]
pub struct Selection {
    #[serde(default)]
    pub q: String,
    pub id: Option<String>,
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
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, kind)], data).into_response()
}
