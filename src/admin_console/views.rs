use super::{ClientSummary, Selection};
use crate::{config::ProviderSettings, users::UserSummary};
use leptos::prelude::*;

fn document(title: &str, body: impl IntoView) -> String {
    format!(
        "<!doctype html>{}",
        view! {
            <html lang="en"><head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <title>{format!("{title} · Pocket-OID")}</title>
                <link rel="stylesheet" href="/admin/assets/console.css"/>
                <script src="/admin/assets/console.js" defer></script>
            </head><body>{body}</body></html>
        }
        .to_html()
    )
}

#[component]
fn Icon(name: &'static str) -> impl IntoView {
    view! { <img class="ui-icon" src=format!("/admin/assets/{name}.svg") alt="" aria-hidden="true"/> }
}

#[component]
fn Status(enabled: bool) -> impl IntoView {
    view! { <span class=if enabled { "status enabled" } else { "status disabled" }>
        <Icon name=if enabled { "enabled" } else { "disabled" }/>
        {if enabled { "Enabled" } else { "Disabled" }}
    </span> }
}

#[component]
fn Navigation(section: &'static str) -> impl IntoView {
    view! {
        <a class="brand" href="/admin/clients" aria-label="Pocket-OID client applications">
            <img src="/admin/assets/logo.svg" alt="Pocket-OID"/><span>"Admin console"</span>
        </a>
        <nav aria-label="Main navigation">{[("clients", "Client applications"), ("users", "Users"), ("provider", "Provider settings")].into_iter().map(|(id, label)| view! {
            <a href=format!("/admin/{id}") class=if section == id { "active" } else { "" } aria-current=(section == id).then_some("page")>
                <Icon name=id/>{label}
            </a>
        }).collect_view()}</nav>
    }
}

#[component]
fn Shell(
    section: &'static str,
    username: String,
    csrf: String,
    #[prop(optional)] detail: bool,
    children: Children,
) -> impl IntoView {
    view! {
        <a class="skip-link" href="#main">"Skip to content"</a>
        <aside class="sidebar"><Navigation section/></aside>
        <dialog class="mobile-drawer" id="navigation" aria-label="Navigation">
            <button type="button" class="icon-button drawer-close" data-close-nav aria-label="Close navigation"><Icon name="close"/></button>
            <Navigation section/>
        </dialog>
        <div class="workspace">
            <div class="topbar">
                <button type="button" class="mobile-menu" data-open-nav aria-controls="navigation" aria-expanded="false"><Icon name="menu"/>"Menu"</button>
                <a class="mobile-brand" href="/admin/clients" aria-label="Pocket-OID home"><img src="/admin/assets/logo.svg" alt="Pocket-OID"/></a>
                <div class="account">
                    <button type="button" class="account-button" aria-haspopup="menu" aria-expanded="false" aria-controls="account-menu" data-account>{username.clone()}<Icon name="chevron"/></button>
                    <div id="account-menu" class="account-menu" role="menu" hidden>
                        <p role="presentation">"Signed in as "<strong>{username}</strong></p>
                        <form method="post" action="/admin/logout">
                            <input type="hidden" name="csrf" value=csrf/>
                            <button role="menuitem" type="submit"><Icon name="logout"/>"Sign out"</button>
                        </form>
                    </div>
                </div>
            </div>
            <main id="main" tabindex="-1" class=if detail { "detail-main" } else { "" }>{children()}</main>
            <footer>"Read-only console"<span>"·"</span>"Configuration loaded at startup"</footer>
        </div>
        <span class="sr-only" id="copy-announcement" role="status" aria-live="polite"></span>
    }
}

#[component]
fn Field(
    #[prop(into)] label: String,
    #[prop(optional)] mono: bool,
    #[prop(optional_no_strip)] copy: Option<String>,
    children: Children,
) -> impl IntoView {
    view! { <div class="field"><dt>{label.clone()}</dt><dd class=if mono { "mono" } else { "" }>{children()}</dd>
        {copy.map(|value| view! { <button type="button" class="copy" data-copy=value aria-label=format!("Copy {label}")>"Copy"</button> })}
    </div> }
}

#[component]
fn Group(title: &'static str, children: Children) -> impl IntoView {
    view! { <section class="group" aria-label=title><h2>{title}</h2><dl>{children()}</dl></section> }
}

#[component]
fn Search(section: &'static str, query: String) -> impl IntoView {
    let label = if section == "clients" {
        "Search client ID or scope"
    } else {
        "Search username or user ID"
    };
    view! { <form class="search" role="search" method="get" action=format!("/admin/{section}")>
        <Icon name="search"/><input type="search" name="q" aria-label=label placeholder=label value=query.clone() autocomplete="off"/>
        <button type="button" data-clear-search aria-label="Clear search" hidden=query.is_empty()><Icon name="close"/></button>
    </form> }
}

fn selected_url(section: &str, id: Option<&str>, query: &str) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    if let Some(id) = id {
        params.append_pair("id", id);
    }
    if !query.is_empty() {
        params.append_pair("q", query);
    }
    let params = params.finish();
    format!(
        "/admin/{section}{}",
        if params.is_empty() {
            String::new()
        } else {
            format!("?{params}")
        }
    )
}

fn matches(text: &str, query: &str) -> bool {
    text.to_lowercase().contains(&query.trim().to_lowercase())
}

pub fn clients(
    username: String,
    csrf: String,
    clients: &[ClientSummary],
    provider: &ProviderSettings,
    selection: Selection,
) -> String {
    if let Some(id) = &selection.id {
        return match clients.iter().find(|c| &c.id == id) {
            Some(client) => client_details(username, csrf, client.clone(), provider, selection.q),
            None => document(
                "Client not found",
                view! { <Shell section="clients" username csrf detail=true><h1>"Client not found"</h1><a href=selected_url("clients", None, &selection.q)>"Back to client applications"</a></Shell> },
            ),
        };
    }
    let query = selection.q;
    let empty = clients.is_empty();
    let count = clients
        .iter()
        .filter(|c| matches(&format!("{} {}", c.id, c.scopes.join(" ")), &query))
        .count();
    let rows = clients.iter().map(|c| {
        let search = format!("{} {}", c.id, c.scopes.join(" "));
        view! { <tr data-search=search.clone() hidden=!matches(&search, &query)>
            <td data-label="Client ID"><a class="id-link" data-detail-link href=selected_url("clients", Some(&c.id), &query)>{c.id.clone()}</a></td>
            <td data-label="Status"><Status enabled=c.enabled/></td>
            <td data-label="Authentication">{c.mode}</td>
            <td data-label="Scopes" class="scopes">{if c.scopes.is_empty() { "No scopes configured".into() } else { c.scopes.join(", ") }}</td>
        </tr> }
    }).collect_view();
    document(
        "Client applications",
        view! {
            <Shell section="clients" username csrf>
                <header class="page-header"><h1>"Client applications"</h1><p>"Inspect registered applications and their authentication settings."</p></header>
                <div class="toolbar"><Search section="clients" query=query.clone()/><span class="count" role="status" data-count="applications">{format!("{count} {} · includes disabled clients", if count == 1 { "application" } else { "applications" })}</span></div>
                <div class="list-detail"><div class="table-area">
                    <table data-filter-table hidden=count == 0><caption class="sr-only">"Registered client applications, including disabled clients"</caption>
                        <thead><tr><th scope="col">"Client ID"</th><th scope="col">"Status"</th><th scope="col">"Authentication"</th><th scope="col">"Scopes"</th></tr></thead><tbody>{rows}</tbody>
                    </table>
                    <div class="state" role="status" hidden=!empty><h2>"No client applications configured."</h2><p>"Configured applications will appear here."</p></div>
                    <div class="state" data-no-results hidden={count > 0 || empty} role="status"><Icon name="search"/><h2 data-no-results-title>{format!("No matches for “{query}”.")}</h2><button class="text-button" type="button" data-clear-search>"Clear search"</button></div>
                </div></div>
            </Shell>
        },
    )
}

fn client_details(
    username: String,
    csrf: String,
    client: ClientSummary,
    provider: &ProviderSettings,
    query: String,
) -> String {
    let title = client.id.clone();
    let algorithm = client
        .algorithm
        .clone()
        .unwrap_or_else(|| provider.signing_algorithm.as_str().into());
    let lifetime = duration(client.lifetime.unwrap_or(provider.token_ttl_seconds));
    let redirects = client.redirects.clone().into_iter().enumerate().map(|(i, url)| view! {
        <Field label=format!("Redirect URL {}", i + 1) mono=true copy=Some(url.clone())>{url.clone()}</Field>
    }).collect_view();
    let scopes = client.scopes.join(", ");
    let scope_copy = (!client.scopes.is_empty()).then(|| client.scopes.join(" "));
    let back = selected_url("clients", None, &query);
    document(
        &title,
        view! {
            <Shell section="clients" username csrf detail=true>
                <div class="breadcrumb"><a href=back data-back-link>"Client applications"</a><span>"/"</span><span>{client.id.clone()}</span></div>
                <header class="page-header detail-header"><h1>{client.id.clone()}</h1><p>"Registered client configuration."</p>
                    <div class="detail-status"><span>"Status: "<Status enabled=client.enabled/></span><span>"Authentication: "<strong>{client.mode}</strong></span></div>
                </header>
                <div class="details">
                    <Group title="Identity">
                        <Field label="Client ID" mono=true copy=Some(client.id.clone())>{client.id}</Field>
                        <Field label="Audience" mono=true copy=client.audience.clone()>{client.audience.unwrap_or_else(|| "Not configured".into())}</Field>
                    </Group>
                    <Group title="Redirect URLs">{redirects}{client.redirects.is_empty().then(|| view! { <div class="field"><dt>"Redirect URLs"</dt><dd class="muted">"No redirect URLs configured."</dd></div> })}</Group>
                    <Group title="Scopes"><Field label="Allowed scopes" mono=true copy=scope_copy>{if scopes.is_empty() { "No scopes configured.".into() } else { scopes }}</Field></Group>
                    <Group title="Authentication">
                        <Field label="PKCE">{if client.pkce { "Required" } else { "Not required" }}</Field>
                        <Field label="Consent">{client.consent}</Field>
                        {client.trusted.map(|trusted| view! { <Field label="Trusted provider" mono=true>{trusted}</Field><Field label="Upstream scopes" mono=true>{client.upstream_scopes.join(", ")}</Field> })}
                    </Group>
                    <Group title="Tokens">
                        <Field label="Signing algorithm"><span class="mono">{algorithm}</span><span class="inheritance">{if client.algorithm.is_some() { "Client override" } else { "Inherited from provider" }}</span></Field>
                        <Field label="Token lifetime">{lifetime}<span class="inheritance">{if client.lifetime.is_some() { "Client override" } else { "Inherited from provider" }}</span></Field>
                    </Group>
                </div>
            </Shell>
        },
    )
}

pub fn users(
    username: String,
    csrf: String,
    users: Option<Vec<UserSummary>>,
    source: &'static str,
    selection: Selection,
) -> String {
    let query = selection.q;
    let error = users.is_none();
    let records = users.unwrap_or_default();
    let selected = selection
        .id
        .as_ref()
        .and_then(|id| records.iter().find(|u| &u.id == id))
        .cloned();
    let count = records
        .iter()
        .filter(|u| matches(&format!("{} {}", u.username, u.id), &query))
        .count();
    let rows = records.iter().map(|u| {
        let search = format!("{} {}", u.username, u.id);
        view! { <tr data-search=search.clone() hidden=!matches(&search, &query) class=if Some(&u.id) == selection.id.as_ref() { "selected" } else { "" }>
            <td data-label="Username"><a class="id-link" data-detail-link href=selected_url("users", Some(&u.id), &query)>{u.username.clone()}</a></td>
            <td data-label="User ID" class="mono">{u.id.clone()}</td><td data-label="Status"><Status enabled=u.enabled/></td>
        </tr> }
    }).collect_view();
    let detail = selection.id.as_ref().filter(|_| !error).map(|_| view! {
        <aside class="user-detail" aria-label="User details"><div class="user-detail-header"><h2>{selected.as_ref().map(|u| u.username.clone()).unwrap_or_else(|| "User not found".into())}</h2>
            <a class="icon-button" href=selected_url("users", None, &query) data-close-user aria-label="Close user details"><Icon name="close"/></a>
        </div>
        {selected.clone().map(|u| view! { <dl>
            <Field label="Username">{u.username.clone()}</Field><Field label="User ID" mono=true copy=Some(u.id.clone())>{u.id.clone()}</Field>
            <Field label="Status"><Status enabled=u.enabled/></Field><Field label="User source">{source}</Field>
        </dl> })}
        {selected.is_none().then(|| view! { <p class="muted">"This user is not available."</p> })}
        </aside>
    });
    document(
        "Users",
        view! { <Shell section="users" username csrf>
            <header class="page-header"><h1>"Users"</h1><p>"Local application users. Administrator accounts and upstream identities are separate."</p>
                <p class="source">"User source: "<strong>{source}</strong>{(source == "JSON").then(|| view! { <span>"All configured JSON users are enabled."</span> })}</p>
            </header>
            <div class="toolbar"><Search section="users" query=query.clone()/></div>
            <span class="sr-only" role="status" data-count="users" hidden=error>{format!("{count} users found")}</span>
            <div class=if selection.id.is_some() && !error { "list-detail has-detail" } else { "list-detail" }><div class="table-area">
                <table data-filter-table hidden=error || count == 0><caption class="sr-only">"Local application users"</caption>
                    <thead><tr><th scope="col">"Username"</th><th scope="col">"User ID"</th><th scope="col">"Status"</th></tr></thead><tbody>{rows}</tbody>
                </table>
                <div class="state error" role="alert" hidden=!error><h2>"Could not load users."</h2><p>"Try again."</p><a class="primary" href=selected_url("users", selection.id.as_deref(), &query)>"Retry"</a></div>
                <div class="state" role="status" hidden=error || !records.is_empty()><h2>"No local users available."</h2><p>"Configured local users will appear here."</p></div>
            <div class="state" data-no-results hidden={error || count > 0 || records.is_empty()} role="status"><Icon name="search"/><h2 data-no-results-title>{format!("No users match “{query}”.")}</h2><button class="text-button" type="button" data-clear-search>"Clear search"</button></div>
            </div>{detail}</div>
        </Shell> },
    )
}

pub fn provider(username: String, csrf: String, provider: &ProviderSettings) -> String {
    let name = provider.name.clone();
    let issuer = provider.issuer.clone();
    let algorithm = provider.signing_algorithm.as_str();
    let lifetime = duration(provider.token_ttl_seconds);
    let background = provider.login_background_color.clone();
    document(
        "Provider settings",
        view! { <Shell section="provider" username csrf>
            <header class="page-header"><h1>"Provider settings"</h1><p>"Current provider configuration."</p></header>
            <div class="details provider">
                <Group title="Identity"><Field label="Provider name">{name}</Field><Field label="Issuer URL" mono=true copy=Some(issuer.clone())>{issuer}</Field></Group>
                <Group title="Tokens"><Field label="Default signing algorithm" mono=true>{algorithm}</Field><Field label="Default token lifetime">{lifetime}</Field></Group>
                <section class="group" aria-label="Login appearance"><h2>"Login appearance"</h2><dl>
                    <Field label="Background color" copy=background.clone()>
                        {background.as_ref().map(|color| view! { <span class="swatch" style=format!("background: {color}") aria-hidden="true"></span> })}
                        <span class="mono">{background.unwrap_or_else(|| "Default background".into())}</span>
                    </Field>
                </dl>
                    <figure class="login-preview"><div class="preview-frame" inert=""><iframe src="/admin/login-preview" title="Current login appearance preview" sandbox="" tabindex="-1" loading="lazy"></iframe></div><figcaption>"Login preview"</figcaption></figure>
                </section>
            </div>
        </Shell> },
    )
}

pub fn login(csrf: String, error: Option<String>) -> String {
    let unavailable = csrf.is_empty();
    document(
        "Administrator sign in",
        view! {
            <main class="admin-sign-in"><a href="/admin"><img src="/admin/assets/logo.svg" alt="Pocket-OID"/></a>
                <h1>"Admin console"</h1><p>"Sign in with your administrator account."</p>
                {error.map(|message| view! { <p class="login-error" role="alert">{message}</p> })}
                <form method="post" action="/admin/login" hidden=unavailable>
                    <input type="hidden" name="csrf" value=csrf/>
                    <label for="username">"Username"</label><input id="username" name="username" autocomplete="username" required maxlength="128"/>
                    <label for="password">"Password"</label><input id="password" name="password" type="password" autocomplete="current-password" required/>
                    <button class="primary" type="submit">"Sign in"</button>
                </form>
                {unavailable.then(|| view! { <a href="/admin/login">"Reload sign in"</a> })}
            </main>
        },
    )
}

fn duration(seconds: u64) -> String {
    let raw = seconds.to_string();
    let grouped: String = raw
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i > 0 && (raw.len() - i).is_multiple_of(3) {
                vec![',', c]
            } else {
                vec![c]
            }
        })
        .collect();
    let (value, unit) = if seconds > 0 && seconds.is_multiple_of(3600) {
        (seconds / 3600, "hour")
    } else if seconds > 0 && seconds.is_multiple_of(60) {
        (seconds / 60, "minute")
    } else {
        (seconds, "second")
    };
    format!(
        "{grouped} seconds ({value} {unit}{})",
        if value == 1 { "" } else { "s" }
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn duration_uses_actual_values() {
        assert_eq!(super::duration(3600), "3,600 seconds (1 hour)");
        assert_eq!(super::duration(900), "900 seconds (15 minutes)");
        assert_eq!(super::duration(61), "61 seconds (61 seconds)");
    }
}
