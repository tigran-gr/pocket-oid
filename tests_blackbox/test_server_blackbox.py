import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _pick_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_get_json(url: str):
    with urllib.request.urlopen(url, timeout=1) as response:
        body = response.read().decode("utf-8")
        payload = json.loads(body) if body else None
        return response.status, payload


def _http_post_form(url: str, form: dict):
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(url, method="POST", data=data)
    req.add_header("content-type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=1) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


def _decode_jwt_unverified(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise AssertionError("expected JWT with three parts")

    def decode_part(part):
        padding = "=" * ((4 - len(part) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode((part + padding).encode("utf-8")))

    return decode_part(parts[0]), decode_part(parts[1])


class ServerProcess:
    def __init__(self, fixture_name: str):
        self.fixture_name = fixture_name
        self.process = None
        self.config_dir = None
        self.base_url = None

    def start(self):
        source_dir = FIXTURES / self.fixture_name
        self.config_dir = Path(tempfile.mkdtemp(prefix="pocket-oid-test-"))
        shutil.copytree(source_dir, self.config_dir, dirs_exist_ok=True)

        port = _pick_free_port()
        provider_path = self.config_dir / "provider.json"
        provider = json.loads(provider_path.read_text())
        provider["listen"] = f"127.0.0.1:{port}"
        provider_path.write_text(json.dumps(provider))

        env = os.environ.copy()
        env["POCKET_OID_CONFIG_DIR"] = str(self.config_dir)
        self.base_url = f"http://127.0.0.1:{port}"
        self.process = subprocess.Popen(
            ["cargo", "run", "--quiet"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        deadline = time.time() + 15
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise AssertionError("server exited early")
            try:
                status, _ = _http_get_json(f"{self.base_url}/readyz")
                if status == 200:
                    return
            except Exception:
                time.sleep(0.2)

        self.stop()
        raise AssertionError("server did not become ready before timeout")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self.config_dir is not None:
            shutil.rmtree(self.config_dir, ignore_errors=True)


class BlackBoxTests(unittest.TestCase):
    def test_startup_readiness_and_token_flow(self):
        server = ServerProcess("config-basic")
        server.start()
        try:
            discovery_status, discovery = _http_get_json(
                f"{server.base_url}/.well-known/openid-configuration"
            )
            self.assertEqual(discovery_status, 200)
            self.assertIn("jwks_uri", discovery)

            jwks_status, jwks = _http_get_json(f"{server.base_url}/jwks.json")
            self.assertEqual(jwks_status, 200)
            self.assertTrue(jwks["keys"])

            token_status, token = _http_post_form(
                f"{server.base_url}/oauth/token",
                {
                    "grant_type": "client_credentials",
                    "client_id": "svc-a",
                    "client_secret": "supersecret",
                },
            )
            self.assertEqual(token_status, 200)
            self.assertEqual(token["token_type"], "Bearer")

            header, claims = _decode_jwt_unverified(token["access_token"])
            self.assertIn("kid", header)
            self.assertEqual(claims["iss"], "https://pocket-oid.local")
            self.assertEqual(claims["sub"], "svc-a")
            self.assertEqual(claims["aud"], "https://api.example.local")
        finally:
            server.stop()

    def test_startup_fails_with_invalid_config(self):
        config_dir = FIXTURES / "config-invalid-clients"
        env = os.environ.copy()
        env["POCKET_OID_CONFIG_DIR"] = str(config_dir)

        process = subprocess.run(
            ["cargo", "run", "--quiet"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=20
        )

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("failed to initialize provider", process.stderr)


if __name__ == "__main__":
    unittest.main()
