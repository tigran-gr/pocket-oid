import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
KEYCLOAK_TOOLS = ROOT / "tools" / "keycloak"
KEYCLOAK_REALM_FIXTURE = (
    ROOT / "tests_blackbox" / "keycloak" / "pocket-oid-realm-realm.json"
)


def _pick_free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_get_json(url: str):
    with urllib.request.urlopen(url, timeout=1) as response:
        body = response.read().decode("utf-8")
        payload = json.loads(body) if body else None
        return response.status, payload


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_get_text(url: str, headers: dict | None = None, follow_redirects: bool = True):
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    opener = urllib.request.build_opener()
    if not follow_redirects:
        opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(req, timeout=1) as response:
            return response.status, response.read().decode("utf-8"), response.headers
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        headers = err.headers
        err.close()
        return err.code, body, headers


def http_post_form_raw(
    url: str,
    form: dict,
    headers: dict | None = None,
    follow_redirects: bool = True,
):
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(url, method="POST", data=data, headers=headers or {})
    req.add_header("content-type", "application/x-www-form-urlencoded")
    opener = urllib.request.build_opener()
    if not follow_redirects:
        opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(req, timeout=1) as response:
            return response.status, response.read().decode("utf-8"), response.headers
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        headers = err.headers
        err.close()
        return err.code, body, headers


def http_post_form(url: str, form: dict):
    status, body, _ = http_post_form_raw(url, form)
    return status, json.loads(body)


def http_json_request(
    url: str, method: str, payload=None, headers: dict | None = None
):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = dict(headers or {})
    if payload is not None:
        request_headers["content-type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=data, headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        err.close()
        return err.code, json.loads(body) if body else None


def decode_jwt_unverified(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise AssertionError("expected JWT with three parts")

    def decode_part(part):
        padding = "=" * ((4 - len(part) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode((part + padding).encode("utf-8")))

    return decode_part(parts[0]), decode_part(parts[1])


def session_cookie(headers) -> str:
    set_cookie = headers.get("set-cookie")
    if not set_cookie:
        raise AssertionError("expected set-cookie header")
    return set_cookie.split(";", 1)[0]


def query_value(url: str, key: str) -> str:
    parsed = urllib.parse.urlparse(url)
    values = urllib.parse.parse_qs(parsed.query).get(key)
    if not values:
        raise AssertionError(f"expected {key} query value in {url}")
    return values[0]


def authorize_path(
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    client_id: str = "svc-a",
    scope: str = "openid default",
    prompt: str | None = None,
) -> str:
    params = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", scope),
        ("state", state),
        ("nonce", nonce),
    ]
    if code_challenge is not None:
        params.append(("code_challenge", code_challenge))
    if code_challenge_method is not None:
        params.append(("code_challenge_method", code_challenge_method))
    if prompt is not None:
        params.append(("prompt", prompt))
    query = "&".join(f"{key}={value.replace(' ', '%20')}" for key, value in params)
    return f"/authorize?{query}"


def enable_openid_scope(
    config_dir: Path, redirect_uri: str | None = None, require_pkce: bool = False
):
    clients_path = config_dir / "clients.json"
    clients = json.loads(clients_path.read_text())
    client = clients[0]
    client["scopes"] = ["default", "openid"]
    client["response_types"] = ["code"]
    if redirect_uri is not None:
        client["redirect_uris"] = [redirect_uri]
    if require_pkce:
        client["require_pkce"] = True
    clients_path.write_text(json.dumps(clients))


def configure_provider_settings(
    config_dir: Path, name: str, issuer: str, background_color=None
):
    provider_path = config_dir / "provider.json"
    provider = json.loads(provider_path.read_text())
    provider["name"] = name
    provider["issuer"] = issuer
    provider["login_background_color"] = background_color
    provider_path.write_text(json.dumps(provider))

    template_path = config_dir / "token_template.json"
    template = json.loads(template_path.read_text())
    template["iss"] = issuer
    template_path.write_text(json.dumps(template))


class CodeFlowCallback:
    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _CallbackHandler)
        self.server.result = None
        self.server.error = None
        self.server.event = threading.Event()
        self.server.token_url = None
        self.server.redirect_uri = self.redirect_uri
        self.server.expected_state = None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.started = False

    @property
    def redirect_uri(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}/callback"

    def start(self, token_url: str, expected_state: str):
        self.server.token_url = token_url
        self.server.expected_state = expected_state
        self.thread.start()
        self.started = True

    def wait(self, timeout: int):
        if not self.server.event.wait(timeout):
            raise AssertionError(
                f"authentication did not complete within {timeout} seconds"
            )
        if self.server.error is not None:
            raise AssertionError(self.server.error)
        return self.server.result

    def stop(self):
        if self.started:
            self.server.shutdown()
        self.server.server_close()
        if self.started:
            self.thread.join(timeout=5)


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_error(404)
            return

        params = urllib.parse.parse_qs(parsed.query)
        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]
        error = params.get("error", [None])[0]

        if error is not None:
            self._finish_with_error(f"authorization error: {error}")
            return
        if state != self.server.expected_state:
            self._finish_with_error("state did not match")
            return
        if code is None:
            self._finish_with_error("authorization code was missing")
            return

        token_status, token = http_post_form(
            self.server.token_url,
            {
                "grant_type": "authorization_code",
                "client_id": "svc-a",
                "client_secret": "supersecret",
                "redirect_uri": self.server.redirect_uri,
                "code": code,
            },
        )
        if token_status != 200:
            self._finish_with_error(
                f"token exchange failed with HTTP {token_status}: {token}"
            )
            return
        if "id_token" not in token:
            self._finish_with_error("token response did not include id_token")
            return

        self.server.result = token
        self.server.event.set()
        self._send_html(200, "Authentication was successful. You can close this tab.")

    def log_message(self, format, *args):
        return

    def _finish_with_error(self, message: str):
        self.server.error = message
        self.server.event.set()
        self._send_html(400, f"Authentication failed: {message}")

    def _send_html(self, status: int, message: str):
        body = f"<!doctype html><html><body>{message}</body></html>".encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ServerProcess:
    def __init__(self, fixture_name: str, configure_config=None):
        self.fixture_name = fixture_name
        self.configure_config = configure_config
        self.process = None
        self.config_dir = None
        self.port = _pick_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"

    def start(self):
        source_dir = FIXTURES / self.fixture_name
        self.config_dir = Path(tempfile.mkdtemp(prefix="pocket-oid-test-"))
        shutil.copytree(source_dir, self.config_dir, dirs_exist_ok=True)

        port = self.port
        provider_path = self.config_dir / "provider.json"
        provider = json.loads(provider_path.read_text())
        provider["listen"] = f"127.0.0.1:{port}"
        provider_path.write_text(json.dumps(provider))
        if self.configure_config is not None:
            self.configure_config(self.config_dir)

        print(f"Starting server with config from {self.config_dir} on port {port}")

        env = os.environ.copy()
        env["POCKET_OID_CONFIG_DIR"] = str(self.config_dir)
        self.process = subprocess.Popen(
            ["cargo", "run", "--quiet"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.time() + 15
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise AssertionError("server exited early")
            try:
                status, _ = http_get_json(f"{self.base_url}/readyz")
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


class KeycloakProcess:
    def __init__(self, realm_name: str, realm_fixture: Path = KEYCLOAK_REALM_FIXTURE):
        self.realm_name = realm_name
        self.realm_fixture = realm_fixture
        self.port = _pick_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.issuer = f"{self.base_url}/realms/{self.realm_name}"
        self.admin_username = "pocket-oid-test-admin"
        self.admin_password = "pocket-oid-test-admin-password"
        self.process = None
        self.run_dir = None
        self.home_dir = None
        self.log_path = None
        self.log_file = None

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    def start(self):
        self._require_java()
        install_dir = self._ensure_installation()
        if not self.realm_fixture.is_file():
            raise AssertionError(f"Keycloak realm fixture is missing: {self.realm_fixture}")

        self.run_dir = Path(tempfile.mkdtemp(prefix="pocket-oid-keycloak-test-"))
        self.home_dir = self.run_dir / install_dir.name
        shutil.copytree(
            install_dir,
            self.home_dir,
            ignore=shutil.ignore_patterns("data"),
        )
        import_dir = self.home_dir / "data" / "import"
        import_dir.mkdir(parents=True)
        shutil.copy2(self.realm_fixture, import_dir / f"{self.realm_name}-realm.json")

        self.log_path = self.run_dir / "keycloak.log"
        self.log_file = self.log_path.open("w", encoding="utf-8")
        env = os.environ.copy()
        env["KC_BOOTSTRAP_ADMIN_USERNAME"] = self.admin_username
        env["KC_BOOTSTRAP_ADMIN_PASSWORD"] = self.admin_password
        command = [
            str(self.home_dir / "bin" / "kc.sh"),
            "start-dev",
            "--import-realm",
            "--db=dev-file",
            "--http-host=127.0.0.1",
            f"--http-port={self.port}",
            f"--hostname={self.base_url}",
        ]
        print(f"Starting Keycloak on port {self.port}")
        self.process = subprocess.Popen(
            command,
            cwd=self.home_dir,
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )

        deadline = time.time() + 90
        while time.time() < deadline:
            if self.process.poll() is not None:
                self._raise_startup_error("Keycloak exited before becoming ready")
            try:
                status, discovery = http_get_json(self.discovery_url)
                if status == 200:
                    if discovery.get("issuer") != self.issuer:
                        self._raise_startup_error(
                            "Keycloak discovery issuer did not match the configured issuer"
                        )
                    return
            except Exception:
                time.sleep(0.5)

        self._raise_startup_error("Keycloak did not become ready before timeout")

    def configure_client_redirect_uri(self, client_id: str, redirect_uri: str):
        token_status, token = http_post_form(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_username,
                "password": self.admin_password,
            },
        )
        if token_status != 200 or "access_token" not in token:
            raise AssertionError(
                f"failed to obtain Keycloak admin token (HTTP {token_status}): {token}"
            )
        headers = {"authorization": f"Bearer {token['access_token']}"}
        query = urllib.parse.urlencode({"clientId": client_id})
        clients_url = f"{self.base_url}/admin/realms/{self.realm_name}/clients?{query}"
        clients_status, clients = http_json_request(clients_url, "GET", headers=headers)
        if clients_status != 200 or not isinstance(clients, list):
            raise AssertionError(
                f"failed to find Keycloak client {client_id!r} (HTTP {clients_status}): {clients}"
            )
        matches = [client for client in clients if client.get("clientId") == client_id]
        if len(matches) != 1:
            raise AssertionError(
                f"expected exactly one Keycloak client {client_id!r}, found {len(matches)}"
            )
        client = matches[0]
        client["redirectUris"] = [redirect_uri]
        update_url = f"{self.base_url}/admin/realms/{self.realm_name}/clients/{client['id']}"
        update_status, update_body = http_json_request(
            update_url, "PUT", payload=client, headers=headers
        )
        if update_status != 204:
            raise AssertionError(
                f"failed to set Keycloak redirect URI (HTTP {update_status}): {update_body}"
            )

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self.log_file is not None:
            self.log_file.close()
        if self.run_dir is not None:
            shutil.rmtree(self.run_dir, ignore_errors=True)

    def _ensure_installation(self) -> Path:
        ensure_script = KEYCLOAK_TOOLS / "ensure-keycloak.sh"
        result = subprocess.run(
            [str(ensure_script)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise AssertionError(
                "failed to prepare the Keycloak standalone distribution:\n"
                f"{result.stderr.strip()}"
            )
        install_dir = Path(result.stdout.strip())
        if not (install_dir / "bin" / "kc.sh").is_file():
            raise AssertionError(
                f"Keycloak helper returned an invalid installation directory: {install_dir}"
            )
        return install_dir

    @staticmethod
    def _require_java():
        java_path = shutil.which("java")
        if java_path is None:
            raise AssertionError(
                "Keycloak requires a compatible Java runtime on PATH; install one before "
                "running POCKET_OID_MANUAL_KEYCLOAK_REAUTH=1."
            )
        java_version = subprocess.run(
            [java_path, "-version"], capture_output=True, text=True, timeout=10
        )
        if java_version.returncode != 0:
            raise AssertionError(
                "Keycloak requires a compatible Java runtime on PATH; `java -version` "
                "did not succeed."
            )

    def _raise_startup_error(self, message: str):
        log_tail = ""
        if self.log_path is not None and self.log_path.exists():
            log_tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        self.stop()
        detail = f"\nKeycloak log tail:\n{log_tail}" if log_tail else ""
        raise AssertionError(f"{message}{detail}")
