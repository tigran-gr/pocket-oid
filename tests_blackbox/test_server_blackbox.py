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
    decode_jwt_unverified,
    enable_openid_scope,
    http_get_json,
    http_get_text,
    http_post_form,
    http_post_form_raw,
    query_value,
    session_cookie,
)


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
