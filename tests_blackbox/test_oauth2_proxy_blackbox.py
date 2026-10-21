"""Pocket-OID as the OIDC provider for a real OAuth2 Proxy process."""

from html.parser import HTMLParser
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from tests_blackbox.blackbox_support import (
    OAuth2ProxyProcess,
    ServerProcess,
    _NoRedirectHandler,
    configure_provider_settings,
    enable_openid_scope,
    http_get_text,
    query_value,
)


class _ReturnToParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.return_to = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "return_to":
            self.return_to = attrs.get("value")


class _ProtectedAppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        body = json.dumps({
            "path": self.path,
            "user": self.headers.get("X-Forwarded-User"),
            "email": self.headers.get("X-Forwarded-Email"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@unittest.skipUnless(
    os.environ.get("POCKET_OID_OAUTH2_PROXY") == "1",
    "set POCKET_OID_OAUTH2_PROXY=1 to run the OAuth2 Proxy interoperability test",
)
class OAuth2ProxyBlackBoxTests(unittest.TestCase):
    def test_pocket_oid_authenticates_user_for_oauth2_proxy(self):
        self._exercise_email_flow("alice@example.test", True, 302)

    def test_oauth2_proxy_rejects_unverified_email(self):
        self._exercise_email_flow("alice@example.test", False, 500)

    def test_oauth2_proxy_rejects_email_outside_allowed_domain(self):
        self._exercise_email_flow("alice@other.test", True, 403)

    def _exercise_email_flow(self, email, email_verified, callback_status):
        app = ThreadingHTTPServer(("127.0.0.1", 0), _ProtectedAppHandler)
        self.addCleanup(app.server_close)
        app.requests = []
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(app.shutdown)
        app_url = f"http://127.0.0.1:{app.server_port}"

        proxy = OAuth2ProxyProcess()
        provider = ServerProcess("config-basic")
        self.addCleanup(provider.stop)
        self.addCleanup(proxy.stop)

        def configure(config_dir):
            configure_provider_settings(config_dir, "Pocket-OID for OAuth2 Proxy", provider.base_url)
            enable_openid_scope(config_dir, proxy.redirect_uri, require_pkce=True)
            clients_path = config_dir / "clients.json"
            clients = json.loads(clients_path.read_text())
            clients[0]["scopes"].append("email")
            clients_path.write_text(json.dumps(clients))
            users_path = config_dir / "users.json"
            users = json.loads(users_path.read_text())
            users["users"][0].update(email=email, email_verified=email_verified)
            users_path.write_text(json.dumps(users))

        provider.configure_config = configure
        provider.start()
        proxy.start(provider.base_url, app_url)

        cookies = CookieJar()
        browser = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookies), _NoRedirectHandler()
        )

        def request(url, form=None):
            data = None if form is None else urllib.parse.urlencode(form).encode()
            req = urllib.request.Request(url, data=data)
            try:
                response = browser.open(req, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, response.read().decode(), response.headers

        protected_url = f"{proxy.base_url}/private?report=summary"
        status, _, _ = http_get_text(f"{proxy.base_url}/oauth2/auth")
        self.assertEqual(status, 401)
        status, _, headers = request(protected_url)
        self.assertEqual(status, 302)
        self.assertEqual(app.requests, [], "anonymous request reached protected app")
        authorize_url = urllib.parse.urljoin(protected_url, headers["Location"])
        self.assertTrue(authorize_url.startswith(f"{provider.base_url}/authorize?"))
        self.assertEqual(query_value(authorize_url, "client_id"), "svc-a")
        self.assertEqual(query_value(authorize_url, "redirect_uri"), proxy.redirect_uri)
        self.assertEqual(query_value(authorize_url, "scope"), "openid email")
        self.assertEqual(query_value(authorize_url, "code_challenge_method"), "S256")
        self.assertTrue(query_value(authorize_url, "code_challenge"))
        self.assertTrue(query_value(authorize_url, "nonce"))
        state = query_value(authorize_url, "state")

        status, login_html, _ = request(authorize_url)
        self.assertEqual(status, 200)
        login_form = _ReturnToParser()
        login_form.feed(login_html)
        self.assertIsNotNone(login_form.return_to)
        status, _, headers = request(f"{provider.base_url}/login", {
            "username": "alice", "password": "password123",
            "return_to": login_form.return_to,
        })
        self.assertEqual(status, 303)
        consent_url = urllib.parse.urljoin(provider.base_url, headers["Location"])
        status, consent_html, _ = request(consent_url)
        self.assertEqual(status, 200)
        consent_form = _ReturnToParser()
        consent_form.feed(consent_html)
        self.assertIsNotNone(consent_form.return_to)
        status, _, headers = request(f"{provider.base_url}/consent", {
            "decision": "approve", "return_to": consent_form.return_to,
        })
        self.assertEqual(status, 303)
        callback_url = headers["Location"]
        self.assertTrue(callback_url.startswith(f"{proxy.redirect_uri}?"))
        self.assertEqual(query_value(callback_url, "state"), state)
        self.assertTrue(query_value(callback_url, "code"))
        self.assertEqual(app.requests, [])

        # OAuth2 Proxy performs the exchange and validates the ID token itself.
        status, _, headers = request(callback_url)
        self.assertEqual(status, callback_status, proxy.log_tail())
        if callback_status != 302:
            self.assertFalse(any(cookie.name == "_pocket_oid_proxy" for cookie in cookies))
            self.assertEqual(app.requests, [])
            status, _, _ = request(f"{proxy.base_url}/oauth2/auth")
            self.assertEqual(status, 401)
            return
        self.assertTrue(any(cookie.name == "_pocket_oid_proxy" for cookie in cookies))
        self.assertEqual(urllib.parse.urljoin(proxy.base_url, headers["Location"]), protected_url)
        status, body, _ = request(protected_url)
        self.assertEqual(status, 200, proxy.log_tail())
        self.assertEqual(json.loads(body), {
            "path": "/private?report=summary", "user": "user-alice", "email": email,
        })
        self.assertEqual(app.requests, ["/private?report=summary"])

        # Subsequent requests must use the proxy session, not a fresh OIDC login.
        status, _, headers = request(f"{proxy.base_url}/oauth2/auth")
        self.assertEqual(status, 202, proxy.log_tail())
        self.assertEqual(headers["X-Auth-Request-User"], "user-alice")
        self.assertEqual(headers["X-Auth-Request-Email"], email)
        cookies.clear()
        status, _, _ = request(f"{proxy.base_url}/oauth2/auth")
        self.assertEqual(status, 401)
        status, _, _ = http_get_text(
            protected_url,
            headers={"X-Forwarded-User": "user-alice", "X-Forwarded-Email": email},
            follow_redirects=False,
        )
        self.assertEqual(status, 302)
        self.assertEqual(app.requests, ["/private?report=summary"])


if __name__ == "__main__":
    unittest.main()
