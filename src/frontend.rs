pub fn login_page(return_to: &str, error: Option<&str>) -> String {
    let error_html = error
        .map(|message| format!("<p>{message}</p>"))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html>
  <head><meta charset=\"utf-8\"><title>Pocket-OID Login</title></head>
  <body>
    <main>
      <h1>Sign in</h1>
      {error_html}
      <form method=\"post\" action=\"/login\">
        <input type=\"hidden\" name=\"return_to\" value=\"{return_to}\" />
        <label for=\"username\">Username</label>
        <input id=\"username\" name=\"username\" type=\"text\" autocomplete=\"username\" required />
        <label for=\"password\">Password</label>
        <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required />
        <button type=\"submit\">Continue</button>
      </form>
    </main>
  </body>
</html>"#
    )
}

pub fn consent_page(return_to: &str, client_id: &str, scope: &str, username: &str) -> String {
    format!(
        r#"<!doctype html>
<html>
  <head><meta charset=\"utf-8\"><title>Pocket-OID Consent</title></head>
  <body>
    <main>
      <h1>Consent</h1>
      <p>{username}, app '{client_id}' is requesting access.</p>
      <p>Requested scopes: {scope}</p>
      <form method=\"post\" action=\"/consent\">
        <input type=\"hidden\" name=\"return_to\" value=\"{return_to}\" />
        <button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>
        <button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>
      </form>
    </main>
  </body>
</html>"#
    )
}
