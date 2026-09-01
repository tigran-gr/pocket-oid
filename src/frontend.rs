fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub fn login_page(
    provider_name: &str,
    return_to: &str,
    error: Option<&str>,
    background_color: Option<&str>,
) -> String {
    let escaped_provider_name = escape_html(provider_name);
    let escaped_return_to = escape_html(return_to);
    let page_background = background_color.map_or_else(
        || {
            "background:\n          radial-gradient(circle at top, rgba(20, 184, 166, 0.14), transparent 34rem),\n          linear-gradient(180deg, #fbfefd 0%, #f2f8f7 100%);".to_string()
        },
        |color| format!("background: {color};"),
    );
    let error_html = error
        .map(|message| {
            format!(
                r#"<div class="error-message" role="alert">{}</div>"#,
                escape_html(message)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escaped_provider_name} Login</title>
    <style>
      :root {{
        color-scheme: light;
        font-family:
          Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f7fbfa;
        color: #102027;
      }}

      * {{
        box-sizing: border-box;
      }}

      body {{
        min-height: 100vh;
        margin: 0;
        {page_background}
      }}

      body,
      input,
      button {{
        font: inherit;
      }}

      .auth-page {{
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 3rem 1.5rem 2rem;
      }}

      .auth-shell {{
        width: min(100%, 28rem);
      }}

      .brand {{
        margin-bottom: 2rem;
        text-align: center;
      }}

      .brand-name {{
        margin: 0;
        color: #111827;
        font-size: 2.35rem;
        font-weight: 760;
        line-height: 1.1;
      }}

      .brand-subtitle {{
        margin: 0.45rem 0 0;
        color: #60717c;
        font-size: 1rem;
      }}

      .auth-panel {{
        padding: 2rem;
        border: 1px solid #d8e8e5;
        border-radius: 1rem;
        background: rgba(255, 255, 255, 0.92);
        box-shadow: 0 1.25rem 3.75rem rgba(15, 82, 78, 0.12);
      }}

      h1 {{
        margin: 0;
        color: #102027;
        font-size: 1.55rem;
        font-weight: 720;
        line-height: 1.2;
      }}

      .intro {{
        margin: 0.55rem 0 1.65rem;
        color: #60717c;
        font-size: 0.98rem;
        line-height: 1.5;
      }}

      .error-message {{
        margin-bottom: 1.25rem;
        padding: 0.9rem 1rem;
        border: 1px solid #fecaca;
        border-radius: 0.7rem;
        background: #fff5f5;
        color: #b42318;
        font-size: 0.95rem;
        line-height: 1.45;
      }}

      .field {{
        margin-bottom: 1.25rem;
      }}

      label {{
        display: block;
        margin-bottom: 0.45rem;
        color: #1f2f37;
        font-size: 0.95rem;
        font-weight: 650;
      }}

      input[type="text"],
      input[type="password"] {{
        width: 100%;
        min-height: 3.25rem;
        padding: 0.85rem 0.95rem;
        border: 1px solid #c7d6d3;
        border-radius: 0.7rem;
        background: #ffffff;
        color: #102027;
        outline: none;
        transition:
          border-color 140ms ease,
          box-shadow 140ms ease,
          background-color 140ms ease;
      }}

      input[type="text"]:focus,
      input[type="password"]:focus {{
        border-color: #0f9f8f;
        background: #fbfffe;
        box-shadow: 0 0 0 0.2rem rgba(20, 184, 166, 0.18);
      }}

      button[type="submit"] {{
        width: 100%;
        min-height: 3.25rem;
        margin-top: 0.35rem;
        border: 0;
        border-radius: 0.7rem;
        background: #0f8f86;
        color: #ffffff;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 0.75rem 1.75rem rgba(15, 143, 134, 0.22);
        transition:
          background-color 140ms ease,
          box-shadow 140ms ease,
          transform 140ms ease;
      }}

      button[type="submit"]:hover {{
        background: #0b766f;
        box-shadow: 0 0.9rem 2rem rgba(15, 143, 134, 0.26);
        transform: translateY(-1px);
      }}

      button[type="submit"]:focus-visible {{
        outline: 0.2rem solid rgba(20, 184, 166, 0.42);
        outline-offset: 0.2rem;
      }}

      .status-note {{
        margin-top: 1.5rem;
        padding-top: 1.25rem;
        border-top: 1px solid #e0ece9;
        color: #60717c;
        font-size: 0.9rem;
        line-height: 1.5;
      }}

      .status-note strong {{
        display: block;
        margin-bottom: 0.2rem;
        color: #0f766e;
        font-size: 0.95rem;
      }}

      @media (max-width: 34rem) {{
        .auth-page {{
          align-items: start;
          padding: 2rem 1rem;
        }}

        .brand {{
          margin-bottom: 1.5rem;
        }}

        .brand-name {{
          font-size: 2rem;
        }}

        .auth-panel {{
          padding: 1.4rem;
          border-radius: 0.85rem;
        }}
      }}
    </style>
  </head>
  <body>
    <main class="auth-page">
      <section class="auth-shell" aria-labelledby="login-title">
        <div class="brand" aria-label="{escaped_provider_name}">
          <p class="brand-name">{escaped_provider_name}</p>
          <p class="brand-subtitle">OpenID Connect Provider</p>
        </div>
        <div class="auth-panel">
          <h1 id="login-title">Sign in to your account</h1>
          <p class="intro">Access {escaped_provider_name}.</p>
          {error_html}
          <form method="post" action="/login">
            <input type="hidden" name="return_to" value="{escaped_return_to}" />
            <div class="field">
              <label for="username">Username</label>
              <input id="username" name="username" type="text" autocomplete="username" required />
            </div>
            <div class="field">
              <label for="password">Password</label>
              <input id="password" name="password" type="password" autocomplete="current-password" required />
            </div>
            <button type="submit">Continue</button>
          </form>
          <p class="status-note">
            <strong>Authorization required</strong>
            Continue with a configured local account to complete this provider request.
          </p>
        </div>
      </section>
    </main>
  </body>
</html>"#
    )
}

pub fn consent_page(return_to: &str, client_id: &str, scope: &str, username: &str) -> String {
    let escaped_return_to = escape_html(return_to);
    let escaped_client_id = escape_html(client_id);
    let escaped_scope = escape_html(scope);
    let escaped_username = escape_html(username);
    format!(
        r#"<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Pocket-OID Consent</title></head>
  <body>
    <main>
      <h1>Consent</h1>
      <p>{escaped_username}, app '{escaped_client_id}' is requesting access.</p>
      <p>Requested scopes: {escaped_scope}</p>
      <form method="post" action="/consent">
        <input type="hidden" name="return_to" value="{escaped_return_to}" />
        <button type="submit" name="decision" value="approve">Approve</button>
        <button type="submit" name="decision" value="deny">Deny</button>
      </form>
    </main>
  </body>
</html>"#
    )
}

pub fn reauth_consent_page(
    transaction_id: &str,
    client_id: &str,
    scope: &str,
    subject: &str,
) -> String {
    let escaped_transaction_id = escape_html(transaction_id);
    let escaped_client_id = escape_html(client_id);
    let escaped_scope = escape_html(scope);
    let escaped_subject = escape_html(subject);
    format!(
        r#"<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Pocket-OID Consent</title></head>
  <body>
    <main>
      <h1>Consent</h1>
      <p>{escaped_subject}, app '{escaped_client_id}' is requesting access.</p>
      <p>Requested scopes: {escaped_scope}</p>
      <form method="post" action="/reauth/consent">
        <input type="hidden" name="transaction_id" value="{escaped_transaction_id}" />
        <button type="submit" name="decision" value="approve">Approve</button>
        <button type="submit" name="decision" value="deny">Deny</button>
      </form>
    </main>
  </body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::{consent_page, escape_html, login_page, reauth_consent_page};

    #[test]
    fn escape_html_escapes_text_and_attribute_sensitive_characters() {
        assert_eq!(
            escape_html(r#"<script data-x="1">&'</script>"#),
            "&lt;script data-x=&quot;1&quot;&gt;&amp;&#39;&lt;/script&gt;"
        );
    }

    #[test]
    fn login_page_renders_post_form_markup() {
        let html = login_page("Pocket-OID", "/authorize?response_type=code", None, None);

        assert!(html.contains(r#"<form method="post" action="/login">"#));
        assert!(html.contains(r#"name="return_to""#));
        assert!(html.contains(r#"<p class="brand-name">Pocket-OID</p>"#));
        assert!(html.contains("Access Pocket-OID."));
        assert!(!html.contains(r#"\""#));
    }

    #[test]
    fn login_page_uses_configured_background_color() {
        let html = login_page(
            "Pocket-OID",
            "/authorize?response_type=code",
            None,
            Some("#1a2b3c"),
        );

        assert!(html.contains("background: #1a2b3c;"));
        assert!(!html.contains("radial-gradient"));
    }

    #[test]
    fn consent_page_renders_post_form_markup() {
        let html = consent_page(
            "/authorize?response_type=code",
            "svc-a",
            "openid default",
            "alice",
        );

        assert!(html.contains(r#"<form method="post" action="/consent">"#));
        assert!(html.contains(r#"name="decision" value="approve""#));
        assert!(!html.contains(r#"\""#));
    }

    #[test]
    fn reauth_consent_page_uses_server_side_transaction_id() {
        let html = reauth_consent_page("transaction-123", "svc-a", "openid", "partner:user-123");

        assert!(html.contains(r#"<form method="post" action="/reauth/consent">"#));
        assert!(html.contains(r#"name="transaction_id" value="transaction-123""#));
        assert!(!html.contains("return_to"));
    }
}
