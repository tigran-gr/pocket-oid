import json
import os
import shutil
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed

from tests_blackbox.blackbox_support import (
    CodeFlowCallback,
    FIXTURES,
    ServerProcess,
    authorize_path,
    decode_jwt_unverified,
    enable_openid_scope,
    http_get_json,
)


def _create_selenium_driver(webdriver):
    browser = os.environ.get("POCKET_OID_SELENIUM_BROWSER", "chrome").lower()
    headless = os.environ.get("POCKET_OID_SELENIUM_HEADLESS", "1") == "1"

    if browser == "chrome":
        options = webdriver.ChromeOptions()
        if headless:
            options.add_argument("--headless=new")
        options.add_argument("--window-size=1280,900")
        return webdriver.Chrome(options=options)

    if browser == "firefox":
        options = webdriver.FirefoxOptions()
        if headless:
            options.add_argument("-headless")
        return webdriver.Firefox(options=options)

    if browser == "safari":
        if headless:
            raise ValueError(
                "Safari does not support headless mode; "
                "set POCKET_OID_SELENIUM_HEADLESS=0"
            )
        return webdriver.Safari()

    raise ValueError(
        "POCKET_OID_SELENIUM_BROWSER must be one of: chrome, firefox, safari"
    )


def _login_and_approve(
    driver, authorize_url, timeout, *, username="alice", password="password123", barrier=None
):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    wait = WebDriverWait(driver, timeout)
    driver.get(authorize_url)
    wait.until(
        EC.visibility_of_element_located((By.NAME, "username"))
    ).send_keys(username)
    driver.find_element(By.NAME, "password").send_keys(password)
    if barrier is not None:
        barrier.wait(timeout=timeout)
    driver.find_element(
        By.CSS_SELECTOR, 'form[action="/login"] button[type="submit"]'
    ).click()
    approve = wait.until(
        EC.element_to_be_clickable(
            (By.CSS_SELECTOR, 'form[action="/consent"] button[value="approve"]')
        )
    )
    if barrier is not None:
        barrier.wait(timeout=timeout)
    approve.click()
    wait.until(
        EC.text_to_be_present_in_element(
            (By.TAG_NAME, "body"), "Authentication was successful"
        )
    )


def _load_jwt_verifier():
    try:
        import jwt
        import cryptography  # noqa: F401; required for asymmetric verification
    except ModuleNotFoundError as error:
        raise AssertionError(
            "JWT verification dependencies are missing; run "
            "'python3 -m pip install -r tests_blackbox/requirements-selenium.txt'"
        ) from error
    return jwt


@unittest.skipUnless(
    os.environ.get("POCKET_OID_SELENIUM_CODE_FLOW") == "1",
    "set POCKET_OID_SELENIUM_CODE_FLOW=1 to run the Selenium browser code-flow tests",
)
class SeleniumBlackBoxTests(unittest.TestCase):
    def setUp(self):
        try:
            from selenium import webdriver
        except ModuleNotFoundError:
            self.fail(
                "Selenium is not installed; run "
                "'python3 -m pip install -r tests_blackbox/requirements-selenium.txt'"
            )
        self.webdriver = webdriver
        self.timeout = int(os.environ.get("POCKET_OID_SELENIUM_TIMEOUT_SECONDS", "30"))

    def test_authorization_code_flow_in_selenium(self):
        state = "state-selenium-blackbox"
        nonce = "nonce-selenium-blackbox"
        callback = CodeFlowCallback()
        server = ServerProcess(
            "config-basic",
            configure_config=lambda config_dir: enable_openid_scope(
                config_dir, callback.redirect_uri
            ),
        )
        driver = None

        try:
            server.start()
            callback.start(f"{server.base_url}/oauth/token", state)
            authorize_url = (
                f"{server.base_url}{authorize_path(callback.redirect_uri, state, nonce)}"
            )
            driver = _create_selenium_driver(self.webdriver)
            driver.set_page_load_timeout(self.timeout)
            _login_and_approve(driver, authorize_url, self.timeout)

            token = callback.wait(self.timeout)
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
            try:
                if driver is not None:
                    driver.quit()
            finally:
                callback.stop()
                server.stop()

    def test_five_users_log_in_concurrently_in_selenium(self):
        if os.environ.get("POCKET_OID_SELENIUM_BROWSER", "chrome").lower() == "safari":
            self.skipTest("the five-browser concurrency test requires Chrome or Firefox")
        jwt = _load_jwt_verifier()
        users = [
            {
                "id": f"user-{name}",
                "username": name,
                "password_plain": f"test-password-{name}",
            }
            for name in ("alice", "bob", "carol", "dave", "eve")
        ]
        callbacks = []
        for _ in users:
            callback = CodeFlowCallback()
            self.addCleanup(callback.stop)
            callbacks.append(callback)

        def configure_users(config_dir):
            enable_openid_scope(config_dir)
            path = config_dir / "clients.json"
            clients = json.loads(path.read_text())
            clients[0]["redirect_uris"] = [c.redirect_uri for c in callbacks]
            clients[0]["consent_mode"] = "always"
            path.write_text(json.dumps(clients))
            (config_dir / "users.json").write_text(
                json.dumps({"provider": "file", "users": users})
            )

        server = ServerProcess("config-basic", configure_config=configure_users)
        self.addCleanup(server.stop)
        server.start()
        status, jwks = http_get_json(f"{server.base_url}/jwks.json")
        self.assertEqual(status, 200)
        self.assertEqual(len(jwks["keys"]), 1)
        jwk = jwks["keys"][0]
        self.assertEqual(jwk["alg"], "RS256")
        key = jwt.PyJWK.from_dict(jwk, algorithm="RS256").key

        # Start browsers before the workers so browser startup cannot stagger logins.
        drivers = []
        for user, callback in zip(users, callbacks):
            callback.start(f"{server.base_url}/oauth/token", f"state-{user['username']}")
            driver = _create_selenium_driver(self.webdriver)
            self.addCleanup(driver.quit)
            driver.set_page_load_timeout(self.timeout)
            drivers.append(driver)

        # All five forms are ready before login, and all five sessions exist before consent.
        barrier = threading.Barrier(len(users))

        def log_in(user, callback, driver):
            try:
                path = authorize_path(
                    callback.redirect_uri,
                    f"state-{user['username']}",
                    f"nonce-{user['username']}",
                )
                _login_and_approve(
                    driver,
                    f"{server.base_url}{path}",
                    self.timeout,
                    username=user["username"],
                    password=user["password_plain"],
                    barrier=barrier,
                )
                token = callback.wait(self.timeout)
                cookie = driver.get_cookie("session_id")
                if cookie is None:
                    raise AssertionError(f"missing session cookie for {user['username']}")
                return token, cookie["value"]
            except Exception:
                # Release other workers immediately if a login fails at either barrier.
                barrier.abort()
                raise

        session_ids = set()
        subjects = set()
        with ThreadPoolExecutor(max_workers=len(users)) as executor:
            futures = {
                executor.submit(log_in, user, callback, driver): user
                for user, callback, driver in zip(users, callbacks, drivers)
            }
            for future in as_completed(futures):
                user = futures[future]
                with self.subTest(username=user["username"]):
                    token, session_id = future.result()
                    self.assertEqual(token["token_type"], "Bearer")
                    self.assertEqual(token["scope"], "openid default")
                    self.assertNotIn(session_id, session_ids)
                    session_ids.add(session_id)
                    for field, audience in (
                        ("id_token", "svc-a"),
                        ("access_token", "https://api.example.local"),
                    ):
                        header = jwt.get_unverified_header(token[field])
                        self.assertEqual(header["alg"], "RS256")
                        self.assertEqual(header["kid"], jwk["kid"])
                        claims = jwt.decode(
                            token[field],
                            key,
                            algorithms=["RS256"],
                            issuer="https://pocket-oid.local",
                            audience=audience,
                            options={"require": ["iss", "sub", "aud", "exp", "iat"]},
                        )
                        self.assertEqual(claims["sub"], user["id"], field)
                        if field == "id_token":
                            self.assertEqual(claims["nonce"], f"nonce-{user['username']}")
                    subjects.add(user["id"])
        self.assertEqual(len(session_ids), 5)
        self.assertEqual(subjects, {user["id"] for user in users})

    def test_three_clients_use_different_signing_algorithms_in_selenium(self):
        jwt = _load_jwt_verifier()

        clients = []
        for algorithm in ("RS256", "ES256", "PS256"):
            client_id = f"selenium-{algorithm.lower()}"
            secret = f"test-secret-{algorithm.lower()}"
            callback = CodeFlowCallback(client_id, secret)
            self.addCleanup(callback.stop)
            clients.append((client_id, secret, algorithm, callback))

        def configure_clients(config_dir):
            path = config_dir / "clients.json"
            template = json.loads(path.read_text())[0]
            path.write_text(json.dumps([
                dict(
                    template,
                    client_id=client_id,
                    client_secret=secret,
                    signing_algorithm=algorithm,
                    scopes=["openid", "default"],
                    response_types=["code"],
                    consent_mode="always",
                    redirect_uris=[callback.redirect_uri],
                )
                for client_id, secret, algorithm, callback in clients
            ]))
            path = config_dir / "provider.json"
            provider = json.loads(path.read_text())
            provider["signing_algorithm"] = "RS256"
            provider["signing_key_paths"] = {
                "ES256": "keys/es256.pem",
                "PS256": "keys/ps256.pem",
            }
            path.write_text(json.dumps(provider))
            shutil.copyfile(FIXTURES / "keys" / "es256.pem", config_dir / "keys" / "es256.pem")
            shutil.copyfile(
                FIXTURES / "keys" / "rsa-alternate.pem", config_dir / "keys" / "ps256.pem"
            )

        server = ServerProcess("config-basic", configure_config=configure_clients)
        self.addCleanup(server.stop)
        server.start()
        status, discovery = http_get_json(
            f"{server.base_url}/.well-known/openid-configuration"
        )
        self.assertEqual(status, 200)
        self.assertCountEqual(
            discovery["id_token_signing_alg_values_supported"], ["RS256", "ES256", "PS256"]
        )
        status, jwks = http_get_json(f"{server.base_url}/jwks.json")
        self.assertEqual(status, 200)
        self.assertEqual(len(jwks["keys"]), 3)
        keys_by_id = {key["kid"]: key for key in jwks["keys"]}
        self.assertEqual(len(keys_by_id), 3)

        driver = _create_selenium_driver(self.webdriver)
        self.addCleanup(driver.quit)
        driver.set_page_load_timeout(self.timeout)
        used_key_ids = set()
        for client_id, _, algorithm, callback in clients:
            with self.subTest(client_id=client_id, algorithm=algorithm):
                state = f"state-{client_id}"
                nonce = f"nonce-{client_id}"
                callback.start(f"{server.base_url}/oauth/token", state)
                # All loopback ports share cookies; require a fresh login for each client.
                driver.delete_all_cookies()
                path = authorize_path(
                    callback.redirect_uri, state, nonce, client_id=client_id, prompt="login"
                )
                _login_and_approve(driver, f"{server.base_url}{path}", self.timeout)
                token = callback.wait(self.timeout)
                self.assertEqual(token["token_type"], "Bearer")
                self.assertEqual(token["scope"], "openid default")
                client_key_ids = set()
                for field, audience in (
                    ("id_token", client_id),
                    ("access_token", "https://api.example.local"),
                ):
                    with self.subTest(token=field):
                        header = jwt.get_unverified_header(token[field])
                        self.assertEqual(header["alg"], algorithm)
                        self.assertIn(header["kid"], keys_by_id)
                        jwk = keys_by_id[header["kid"]]
                        self.assertEqual(jwk["alg"], algorithm)
                        self.assertEqual(jwk["use"], "sig")
                        self.assertEqual(jwk["kty"], "EC" if algorithm == "ES256" else "RSA")
                        key = jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
                        claims = jwt.decode(
                            token[field],
                            key,
                            algorithms=[algorithm],
                            issuer="https://pocket-oid.local",
                            audience=audience,
                            options={"require": ["iss", "sub", "aud", "exp", "iat"]},
                        )
                        self.assertEqual(claims["sub"], "user-alice")
                        if field == "id_token":
                            self.assertEqual(claims["nonce"], nonce)
                        client_key_ids.add(header["kid"])
                self.assertEqual(len(client_key_ids), 1)
                used_key_ids.update(client_key_ids)
        self.assertEqual(used_key_ids, set(keys_by_id))


if __name__ == "__main__":
    unittest.main()
