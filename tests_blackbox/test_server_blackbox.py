import base64
import hashlib
import json
import os
import subprocess
import time
import unittest
import webbrowser

from tests_blackbox.blackbox_support import (
    FIXTURES,
    ROOT,
    CodeFlowCallback,
    ServerProcess,
    authorize_path,
    configure_provider_settings,
    decode_jwt_unverified,
    enable_openid_scope,
    http_get_json,
    http_get_text,
    http_post_form,
    http_post_form_raw,
    query_value,
    session_cookie,
)


UPSTREAM_PROVIDER_ID = "manual-upstream"
UPSTREAM_CLIENT_ID = "pocket-oid-proxy"
UPSTREAM_CLIENT_SECRET = "upstream-secret"
UPSTREAM_LOGIN_BACKGROUND_COLOR = "#4f46e5"


def _configure_manual_reauth_upstream(
    config_dir, upstream_base_url: str, downstream_base_url: str
):
    configure_provider_settings(
        config_dir,
        "Manual Upstream Pocket-OID",
        upstream_base_url,
        UPSTREAM_LOGIN_BACKGROUND_COLOR,
    )
    clients = [
        {
            "client_id": UPSTREAM_CLIENT_ID,
            "client_secret": UPSTREAM_CLIENT_SECRET,
            "audience": "https://upstream-api.example.local",
            "scopes": ["openid", "email"],
            "redirect_uris": [
                f"{downstream_base_url}/reauth/callback/{UPSTREAM_PROVIDER_ID}"
            ],
            "response_types": ["code"],
            "require_pkce": True,
            "consent_mode": "skip",
            "metadata": {"tenant": "manual-upstream"},
        }
    ]
    (config_dir / "clients.json").write_text(json.dumps(clients))


def _configure_manual_reauth_downstream(
    config_dir,
    downstream_base_url: str,
    upstream_base_url: str,
    callback_redirect_uri: str,
):
    configure_provider_settings(
        config_dir,
        "Manual Downstream Pocket-OID",
        downstream_base_url,
    )
    clients = [
        {
            "client_id": "svc-a",
            "client_secret": "supersecret",
            "audience": "https://api.example.local",
            "scopes": ["openid", "default"],
            "redirect_uris": [callback_redirect_uri],
            "response_types": ["code"],
            "metadata": {"tenant": "manual-downstream"},
            "auth_mode": "re_auth",
            "re_auth": {
                "provider_id": UPSTREAM_PROVIDER_ID,
                "upstream_scopes": ["openid", "email"],
                "consent": "local",
            },
        }
    ]
    (config_dir / "clients.json").write_text(json.dumps(clients))
    trusted_providers = [
        {
            "provider_id": UPSTREAM_PROVIDER_ID,
            "type": "oidc",
            "issuer": upstream_base_url,
            "client_id": UPSTREAM_CLIENT_ID,
            "client_secret": UPSTREAM_CLIENT_SECRET,
            "redirect_uri": (
                f"{downstream_base_url}/reauth/callback/{UPSTREAM_PROVIDER_ID}"
            ),
            "token_endpoint_auth_method": "client_secret_post",
            "require_pkce": True,
        }
    ]
    (config_dir / "trusted_providers.json").write_text(json.dumps(trusted_providers))


class BlackBoxTests(unittest.TestCase):
    def test_startup_readiness_and_token_flow(self):
        server = ServerProcess("config-basic")
        server.start()
        try:
            discovery_status, discovery = http_get_json(
                f"{server.base_url}/.well-known/openid-configuration"
            )
            self.assertEqual(discovery_status, 200)
            self.assertIn("jwks_uri", discovery)

            jwks_status, jwks = http_get_json(f"{server.base_url}/jwks.json")
            self.assertEqual(jwks_status, 200)
            self.assertTrue(jwks["keys"])

            token_status, token = http_post_form(
                f"{server.base_url}/oauth/token",
                {
                    "grant_type": "client_credentials",
                    "client_id": "svc-a",
                    "client_secret": "supersecret",
                },
            )

            self.assertEqual(token_status, 200)
            self.assertEqual(token["token_type"], "Bearer")

            header, claims = decode_jwt_unverified(token["access_token"])
            self.assertIn("kid", header)
            self.assertEqual(claims["iss"], "https://pocket-oid.local")
            self.assertEqual(claims["sub"], "svc-a")
            self.assertEqual(claims["aud"], "https://api.example.local")
        finally:
            server.stop()

    def test_authorization_code_flow_returns_id_token(self):
        server = ServerProcess("config-basic", configure_config=enable_openid_scope)
        server.start()
        try:
            redirect_uri = "https://app.example.local/callback"
            state = "state-blackbox"
            nonce = "nonce-blackbox"
            request_path = authorize_path(redirect_uri, state, nonce)

            login_status, _, _ = http_get_text(f"{server.base_url}{request_path}")
            self.assertEqual(login_status, 200)

            login_status, _, login_headers = http_post_form_raw(
                f"{server.base_url}/login",
                {
                    "username": "alice",
                    "password": "password123",
                    "return_to": request_path,
                },
                follow_redirects=False,
            )
            self.assertEqual(login_status, 303)
            cookie = session_cookie(login_headers)

            consent_status, _, _ = http_get_text(
                f"{server.base_url}{request_path}",
                headers={"cookie": cookie},
            )
            self.assertEqual(consent_status, 200)

            consent_status, _, consent_headers = http_post_form_raw(
                f"{server.base_url}/consent",
                {"decision": "approve", "return_to": request_path},
                headers={"cookie": cookie},
                follow_redirects=False,
            )
            self.assertEqual(consent_status, 303)
            callback_url = consent_headers.get("location")
            self.assertTrue(callback_url.startswith(redirect_uri))
            self.assertEqual(query_value(callback_url, "state"), state)
            code = query_value(callback_url, "code")

            token_status, token = http_post_form(
                f"{server.base_url}/oauth/token",
                {
                    "grant_type": "authorization_code",
                    "client_id": "svc-a",
                    "client_secret": "supersecret",
                    "redirect_uri": redirect_uri,
                    "code": code,
                },
            )
            self.assertEqual(token_status, 200)
            self.assertEqual(token["token_type"], "Bearer")
            self.assertEqual(token["scope"], "openid default")
            self.assertIn("id_token", token)

            jwks_status, jwks = http_get_json(f"{server.base_url}/jwks.json")
            self.assertEqual(jwks_status, 200)

            header, claims = decode_jwt_unverified(token["id_token"])
            self.assertIn("kid", header)
            self.assertTrue(any(key["kid"] == header["kid"] for key in jwks["keys"]))
            self.assertEqual(claims["iss"], "https://pocket-oid.local")
            self.assertEqual(claims["sub"], "user-alice")
            self.assertEqual(claims["aud"], "svc-a")
            self.assertEqual(claims["nonce"], nonce)
            self.assertGreater(claims["exp"], int(time.time()))
            self.assertLessEqual(abs(int(time.time()) - claims["iat"]), 30)
        finally:
            server.stop()

    def test_authorization_code_flow_with_s256_pkce(self):
        server = ServerProcess(
            "config-basic",
            configure_config=lambda config_dir: enable_openid_scope(
                config_dir, require_pkce=True
            ),
        )
        server.start()
        try:
            redirect_uri = "https://app.example.local/callback"
            state = "state-pkce-blackbox"
            nonce = "nonce-pkce-blackbox"
            verifier = "a-pkce-verifier-used-only-by-this-test"
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            ).rstrip(b"=").decode("ascii")
            request_path = authorize_path(
                redirect_uri,
                state,
                nonce,
                code_challenge=challenge,
                code_challenge_method="S256",
            )

            login_status, _, _ = http_get_text(f"{server.base_url}{request_path}")
            self.assertEqual(login_status, 200)

            login_status, _, login_headers = http_post_form_raw(
                f"{server.base_url}/login",
                {
                    "username": "alice",
                    "password": "password123",
                    "return_to": request_path,
                },
                follow_redirects=False,
            )
            self.assertEqual(login_status, 303)
            cookie = session_cookie(login_headers)

            def issue_code():
                consent_status, _, _ = http_get_text(
                    f"{server.base_url}{request_path}",
                    headers={"cookie": cookie},
                )
                self.assertEqual(consent_status, 200)
                consent_status, _, consent_headers = http_post_form_raw(
                    f"{server.base_url}/consent",
                    {"decision": "approve", "return_to": request_path},
                    headers={"cookie": cookie},
                    follow_redirects=False,
                )
                self.assertEqual(consent_status, 303)
                callback_url = consent_headers.get("location")
                self.assertTrue(callback_url.startswith(redirect_uri))
                self.assertEqual(query_value(callback_url, "state"), state)
                return query_value(callback_url, "code")

            incorrect_verifier_status, incorrect_verifier_error = http_post_form(
                f"{server.base_url}/oauth/token",
                {
                    "grant_type": "authorization_code",
                    "client_id": "svc-a",
                    "client_secret": "supersecret",
                    "redirect_uri": redirect_uri,
                    "code": issue_code(),
                    "code_verifier": "incorrect-verifier",
                },
            )
            self.assertEqual(incorrect_verifier_status, 400)
            self.assertEqual(incorrect_verifier_error["error"], "invalid_grant")
            self.assertEqual(
                incorrect_verifier_error["error_description"],
                "pkce verification failed",
            )

            token_status, token = http_post_form(
                f"{server.base_url}/oauth/token",
                {
                    "grant_type": "authorization_code",
                    "client_id": "svc-a",
                    "client_secret": "supersecret",
                    "redirect_uri": redirect_uri,
                    "code": issue_code(),
                    "code_verifier": verifier,
                },
            )
            self.assertEqual(token_status, 200)
            self.assertEqual(token["token_type"], "Bearer")
            self.assertEqual(token["scope"], "openid default")
            self.assertIn("id_token", token)
        finally:
            server.stop()

    @unittest.skipUnless(
        os.environ.get("POCKET_OID_MANUAL_CODE_FLOW") == "1",
        "set POCKET_OID_MANUAL_CODE_FLOW=1 to run the manual browser code-flow test",
    )
    def test_manual_authorization_code_flow_in_browser(self):
        state = "state-manual-blackbox"
        nonce = "nonce-manual-blackbox"
        callback = CodeFlowCallback()
        server = ServerProcess(
            "config-basic",
            configure_config=lambda config_dir: enable_openid_scope(
                config_dir, callback.redirect_uri
            ),
        )

        try:
            server.start()
            callback.start(f"{server.base_url}/oauth/token", state)
            authorize_url = (
                f"{server.base_url}{authorize_path(callback.redirect_uri, state, nonce)}"
            )
            timeout = int(os.environ.get("POCKET_OID_MANUAL_TIMEOUT_SECONDS", "300"))

            print("\nManual authorization code flow test")
            print(f"Opening: {authorize_url}")
            print(
                "Login with username 'alice' and password 'password123', "
                "then approve consent."
            )
            if not webbrowser.open(authorize_url):
                print(
                    "Browser did not open automatically; "
                    "paste the URL above into your browser."
                )

            token = callback.wait(timeout)
            self.assertEqual(token["token_type"], "Bearer")
            self.assertEqual(token["scope"], "openid default")

            header, claims = decode_jwt_unverified(token["id_token"])
            self.assertIn("kid", header)
            self.assertEqual(claims["iss"], "https://pocket-oid.local")
            self.assertEqual(claims["sub"], "user-alice")
            self.assertEqual(claims["aud"], "svc-a")
            self.assertEqual(claims["nonce"], nonce)
            self.assertGreater(claims["exp"], int(time.time()))
        finally:
            callback.stop()
            server.stop()

    @unittest.skipUnless(
        os.environ.get("POCKET_OID_MANUAL_REAUTH") == "1",
        "set POCKET_OID_MANUAL_REAUTH=1 to run the manual re-auth browser test",
    )
    def test_manual_reauth_flow_in_browser(self):
        state = "state-manual-reauth"
        nonce = "nonce-manual-reauth"
        callback = CodeFlowCallback()
        downstream = ServerProcess("config-basic")
        upstream = ServerProcess("config-basic")
        upstream.configure_config = lambda config_dir: _configure_manual_reauth_upstream(
            config_dir, upstream.base_url, downstream.base_url
        )
        downstream.configure_config = (
            lambda config_dir: _configure_manual_reauth_downstream(
                config_dir,
                downstream.base_url,
                upstream.base_url,
                callback.redirect_uri,
            )
        )

        try:
            upstream.start()
            downstream.start()
            callback.start(f"{downstream.base_url}/oauth/token", state)
            visual_check_verifier = "manual-reauth-visual-check-verifier"
            visual_check_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(visual_check_verifier.encode("ascii")).digest()
            ).rstrip(b"=").decode("ascii")
            upstream_login_path = authorize_path(
                f"{downstream.base_url}/reauth/callback/{UPSTREAM_PROVIDER_ID}",
                "state-visual-check",
                "nonce-visual-check",
                code_challenge=visual_check_challenge,
                code_challenge_method="S256",
                client_id=UPSTREAM_CLIENT_ID,
                scope="openid email",
                prompt="login",
            )
            login_status, login_html, _ = http_get_text(
                f"{upstream.base_url}{upstream_login_path}"
            )
            self.assertEqual(login_status, 200)
            self.assertIn(
                f"background: {UPSTREAM_LOGIN_BACKGROUND_COLOR};", login_html
            )

            authorize_url = (
                f"{downstream.base_url}"
                f"{authorize_path(callback.redirect_uri, state, nonce, prompt='login')}"
            )
            timeout = int(os.environ.get("POCKET_OID_MANUAL_TIMEOUT_SECONDS", "300"))

            print("\nManual re-authentication flow test")
            print(f"Opening downstream authorization request: {authorize_url}")
            print(
                "You will be redirected to the purple 'Manual Upstream Pocket-OID' "
                f"login page (background {UPSTREAM_LOGIN_BACKGROUND_COLOR})."
            )
            print(
                "Log in there with username 'alice' and password 'password123', "
                "then approve the downstream consent screen."
            )
            if not webbrowser.open(authorize_url):
                print(
                    "Browser did not open automatically; paste the URL above into your browser."
                )

            token = callback.wait(timeout)
            self.assertEqual(token["token_type"], "Bearer")
            self.assertEqual(token["scope"], "openid default")
            self.assertIn("id_token", token)

            header, claims = decode_jwt_unverified(token["id_token"])
            self.assertIn("kid", header)
            self.assertEqual(claims["iss"], downstream.base_url)
            self.assertEqual(
                claims["sub"], f"{UPSTREAM_PROVIDER_ID}:user-alice"
            )
            self.assertEqual(claims["aud"], "svc-a")
            self.assertEqual(claims["nonce"], nonce)
            self.assertGreater(claims["exp"], int(time.time()))
        finally:
            callback.stop()
            downstream.stop()
            upstream.stop()

    def test_startup_fails_with_invalid_config(self):
        config_dir = FIXTURES / "config-invalid-clients"
        env = os.environ.copy()
        env["POCKET_OID_CONFIG_DIR"] = str(config_dir)

        process = subprocess.run(
            ["cargo", "run", "--quiet"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("failed to initialize provider", process.stderr)


if __name__ == "__main__":
    unittest.main()
