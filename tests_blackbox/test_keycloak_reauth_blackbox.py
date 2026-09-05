import json
import os
import time
import unittest
import webbrowser

from tests_blackbox.blackbox_support import (
    CodeFlowCallback,
    KeycloakProcess,
    ServerProcess,
    authorize_path,
    configure_provider_settings,
    decode_jwt_unverified,
    http_get_json,
)


KEYCLOAK_REALM = "pocket-oid-reauth"
KEYCLOAK_PROVIDER_ID = "keycloak-local"
KEYCLOAK_CLIENT_ID = "pocket-oid-proxy"
KEYCLOAK_CLIENT_SECRET = "keycloak-upstream-secret"
KEYCLOAK_USER_ID = "ff32a9de-d7f1-4dcd-bd4a-2c5ff1c5bdee"


def _configure_keycloak_reauth_downstream(
    config_dir, downstream_base_url: str, keycloak_issuer: str, callback_redirect_uri: str
):
    configure_provider_settings(
        config_dir,
        "Manual Keycloak Re-Auth Downstream",
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
            "metadata": {"tenant": "manual-keycloak-downstream"},
            "auth_mode": "re_auth",
            "re_auth": {
                "provider_id": KEYCLOAK_PROVIDER_ID,
                "upstream_scopes": ["openid", "email"],
                "consent": "skip",
            },
        }
    ]
    (config_dir / "clients.json").write_text(json.dumps(clients))
    trusted_providers = [
        {
            "provider_id": KEYCLOAK_PROVIDER_ID,
            "type": "oidc",
            "issuer": keycloak_issuer,
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "redirect_uri": (
                f"{downstream_base_url}/reauth/callback/{KEYCLOAK_PROVIDER_ID}"
            ),
            "token_endpoint_auth_method": "client_secret_post",
            "require_pkce": True,
        }
    ]
    (config_dir / "trusted_providers.json").write_text(json.dumps(trusted_providers))


class KeycloakReauthBlackBoxTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("POCKET_OID_MANUAL_KEYCLOAK_REAUTH") == "1",
        "set POCKET_OID_MANUAL_KEYCLOAK_REAUTH=1 to run the Keycloak re-auth browser test",
    )
    def test_manual_reauth_flow_with_keycloak_upstream(self):
        state = "state-manual-keycloak-reauth"
        nonce = "nonce-manual-keycloak-reauth"
        callback = CodeFlowCallback()
        keycloak = KeycloakProcess(KEYCLOAK_REALM)
        downstream = ServerProcess("config-basic")

        try:
            keycloak.start()
            upstream_callback_uri = (
                f"{downstream.base_url}/reauth/callback/{KEYCLOAK_PROVIDER_ID}"
            )
            keycloak.configure_client_redirect_uri(
                KEYCLOAK_CLIENT_ID, upstream_callback_uri
            )
            downstream.configure_config = (
                lambda config_dir: _configure_keycloak_reauth_downstream(
                    config_dir,
                    downstream.base_url,
                    keycloak.issuer,
                    callback.redirect_uri,
                )
            )
            downstream.start()
            callback.start(f"{downstream.base_url}/oauth/token", state)

            discovery_status, discovery = http_get_json(keycloak.discovery_url)
            self.assertEqual(discovery_status, 200)
            self.assertEqual(discovery["issuer"], keycloak.issuer)
            self.assertIn("authorization_endpoint", discovery)
            self.assertIn("token_endpoint", discovery)
            self.assertIn("jwks_uri", discovery)

            authorize_url = (
                f"{downstream.base_url}"
                f"{authorize_path(callback.redirect_uri, state, nonce, prompt='login')}"
            )
            timeout = int(os.environ.get("POCKET_OID_MANUAL_TIMEOUT_SECONDS", "300"))

            print("\nManual Keycloak re-authentication flow test")
            print(f"Opening downstream authorization request: {authorize_url}")
            print(
                "You will be redirected to the Keycloak login page for "
                f"the '{KEYCLOAK_REALM}' realm."
            )
            print(
                "Log in with username 'keycloak-alice' and password "
                "'keycloak-password'. Pocket-OID will return to the test callback "
                "without displaying a consent screen."
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
                claims["sub"], f"{KEYCLOAK_PROVIDER_ID}:{KEYCLOAK_USER_ID}"
            )
            self.assertEqual(claims["aud"], "svc-a")
            self.assertEqual(claims["nonce"], nonce)
            self.assertGreater(claims["exp"], int(time.time()))
        finally:
            callback.stop()
            downstream.stop()
            keycloak.stop()


if __name__ == "__main__":
    unittest.main()
