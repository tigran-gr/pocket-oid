import json
import os
import shutil
import sqlite3
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from tests_blackbox.blackbox_support import (
    CodeFlowCallback,
    FIXTURES,
    ServerProcess,
    authorize_path,
    configure_provider_settings,
    decode_jwt_unverified,
    enable_openid_scope,
    http_get_json,
)


def _configure_admin_fixture(config_dir, username):
    """Create an isolated administrator using the fixture's password123 hash."""
    (config_dir / "admins.json").write_text(
        json.dumps({"provider": "sqlite", "path": "data/admins.sqlite3"})
    )
    password_hash = json.loads((config_dir / "users.json").read_text())["users"][0][
        "password_hash"
    ]
    (config_dir / "data").mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(config_dir / "data" / "admins.sqlite3")
    try:
        database.executescript(
            """
            CREATE TABLE admins (
                id TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            PRAGMA user_version = 1;
            """
        )
        database.execute(
            "INSERT INTO admins (id, username, password_hash) VALUES (?, ?, ?)",
            ("selenium-admin-id", username, password_hash),
        )
        database.commit()
    finally:
        database.close()


def _configure_admin_lists(config_dir, username, issuer, sqlite=True):
    _configure_admin_fixture(config_dir, username)
    configure_provider_settings(config_dir, "Pocket-OID Lists", issuer)
    clients = []
    for name, enabled, upstream, scope in [
        ("zebra", True, False, "portal"),
        ("alpha", False, False, "reports"),
        ("ALPHA", True, True, "portal"),
        ("Beta", False, True, "portal"),
        ("beta", True, True, "portal"),
        ("Zulu", True, True, "service"),
    ]:
        client = {"client_id": name, "client_secret": "fixture-secret",
                  "enabled": enabled, "scopes": [scope]}
        if upstream:
            client.update(auth_mode="re_auth", re_auth={
                "provider_id": "partner", "upstream_scopes": ["openid"],
            })
        clients.append(client)
    (config_dir / "clients.json").write_text(json.dumps(clients))
    (config_dir / "trusted_providers.json").write_text(json.dumps([{
        "provider_id": "partner", "type": "oidc", "issuer": "https://upstream.example",
        "client_id": "pocket", "client_secret": "fixture-secret",
        "redirect_uri": f"{issuer}/reauth/callback/partner",
    }]))
    password_hash = json.loads((config_dir / "users.json").read_text())["users"][0]["password_hash"]
    users = [("user-1", "ALICE", True), ("user-2", "alice", False),
             ("user-3", "Bob", True), ("user-4", "zebra", False)]
    if sqlite:
        database = sqlite3.connect(config_dir / "data" / "users.sqlite3")
        try:
            database.executescript("""
                CREATE TABLE users (
                    id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                PRAGMA user_version = 1;
            """)
            database.executemany(
                "INSERT INTO users (id, username, password_hash, enabled) VALUES (?, ?, ?, ?)",
                [(uid, name, password_hash, enabled) for uid, name, enabled in users],
            )
            database.commit()
        finally:
            database.close()
        config = {"provider": "sqlite", "path": "data/users.sqlite3"}
    else:
        config = {"provider": "file", "users": [
            {"id": uid, "username": name, "password_hash": password_hash}
            for uid, name, _ in users
        ]}
    (config_dir / "users.json").write_text(json.dumps(config))


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

    def test_administrator_changes_password_in_web_console(self):
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        username = "selenium-password-admin"
        old_password = "password123"
        new_password = "selenium-new-admin-password"
        server = ServerProcess("config-basic")

        def configure_admin(config_dir):
            _configure_admin_fixture(config_dir, username)
            configure_provider_settings(
                config_dir, "Pocket-OID Selenium", server.base_url
            )

        server.configure_config = configure_admin
        driver = None
        try:
            server.start()
            driver = _create_selenium_driver(self.webdriver)
            driver.set_page_load_timeout(self.timeout)
            wait = WebDriverWait(driver, self.timeout)

            driver.get(f"{server.base_url}/admin/login")
            wait.until(EC.visibility_of_element_located((By.NAME, "username"))).send_keys(
                username
            )
            driver.find_element(By.NAME, "password").send_keys(old_password)
            driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
            wait.until(EC.url_contains("/admin/clients"))

            driver.find_element(By.CSS_SELECTOR, "[data-account]").click()
            wait.until(
                EC.element_to_be_clickable(
                    (By.CSS_SELECTOR, 'a[href="/admin/account/password"]')
                )
            ).click()
            wait.until(EC.visibility_of_element_located((By.ID, "current-password")))

            driver.find_element(By.ID, "current-password").send_keys(old_password)
            driver.find_element(By.ID, "new-password").send_keys(new_password)
            driver.find_element(By.ID, "confirm-password").send_keys("does-not-match")
            driver.find_element(
                By.CSS_SELECTOR, 'form[action="/admin/account/password"] button[type="submit"]'
            ).click()
            wait.until(
                EC.text_to_be_present_in_element(
                    (By.ID, "password-error"), "New passwords do not match."
                )
            )
            for field_id in ("current-password", "new-password", "confirm-password"):
                self.assertEqual(driver.find_element(By.ID, field_id).get_attribute("value"), "")

            driver.find_element(By.ID, "current-password").send_keys(old_password)
            driver.find_element(By.ID, "new-password").send_keys(new_password)
            driver.find_element(By.ID, "confirm-password").send_keys(new_password)
            driver.find_element(
                By.CSS_SELECTOR, 'form[action="/admin/account/password"] button[type="submit"]'
            ).click()
            wait.until(EC.url_contains("/admin/login?password_changed=1"))
            self.assertIn("Your password was changed", driver.find_element(By.TAG_NAME, "body").text)

            driver.find_element(By.NAME, "username").send_keys(username)
            driver.find_element(By.NAME, "password").send_keys(old_password)
            driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
            wait.until(
                EC.text_to_be_present_in_element(
                    (By.TAG_NAME, "body"), "Invalid administrator username or password."
                )
            )
            driver.find_element(By.NAME, "username").clear()
            driver.find_element(By.NAME, "username").send_keys(username)
            driver.find_element(By.NAME, "password").send_keys(new_password)
            driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
            wait.until(EC.url_contains("/admin/clients"))
            self.assertIn(username, driver.find_element(By.CSS_SELECTOR, "[data-account]").text)
        finally:
            try:
                if driver is not None:
                    driver.quit()
            finally:
                server.stop()

    def test_provider_connection_details_copy_in_desktop_and_narrow_viewports(self):
        if os.environ.get("POCKET_OID_SELENIUM_BROWSER", "chrome").lower() != "chrome":
            self.skipTest("clipboard permission control in this test requires Chrome")
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        username = "selenium-connection-admin"
        issuer = "http://public-identity.example.test/organizations/a-long-tenant-path/pocket-oid/"

        def configure_admin(config_dir):
            _configure_admin_fixture(config_dir, username)
            configure_provider_settings(config_dir, "Pocket-OID Selenium", issuer)

        server = ServerProcess("config-basic", configure_config=configure_admin)
        self.addCleanup(server.stop)
        server.start()
        _, metadata = http_get_json(f"{server.base_url}/.well-known/openid-configuration")
        urls = {
            "Discovery URL": issuer.rstrip("/") + "/.well-known/openid-configuration",
            "Authorization endpoint": metadata["authorization_endpoint"],
            "Token endpoint": metadata["token_endpoint"],
            "JWKS URL": metadata["jwks_uri"],
        }
        driver = _create_selenium_driver(self.webdriver)
        self.addCleanup(driver.quit)
        driver.set_page_load_timeout(self.timeout)
        wait = WebDriverWait(driver, self.timeout)
        driver.execute_cdp_cmd("Browser.grantPermissions", {
            "origin": server.base_url,
            "permissions": ["clipboardReadWrite", "clipboardSanitizedWrite"],
        })
        driver.get(f"{server.base_url}/admin/provider")
        wait.until(EC.url_contains("/admin/login"))
        driver.find_element(By.NAME, "username").send_keys(username)
        driver.find_element(By.NAME, "password").send_keys("password123")
        driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        wait.until(EC.url_contains("/admin/clients"))
        driver.find_element(By.CSS_SELECTOR, '.sidebar a[href="/admin/provider"]').click()
        wait.until(EC.visibility_of_element_located((By.ID, "connection-heading")))

        for width, name in [(1280, "desktop"), (390, "narrow")]:
            with self.subTest(viewport=name):
                driver.set_window_size(width, 1200)
                # Chrome can clamp its outer window to 500px; set the actual viewport too.
                driver.execute_cdp_cmd("Emulation.setDeviceMetricsOverride", {
                    "width": width, "height": 1200, "deviceScaleFactor": 1, "mobile": False,
                })
                self.assertEqual(driver.execute_script("return window.innerWidth"), width)
                for label, expected in urls.items():
                    button = driver.find_element(By.CSS_SELECTOR, f'button[aria-label="Copy {label}"]')
                    self.assertEqual(button.get_attribute("data-copy"), expected)
                    value = button.find_element(By.XPATH, "../dd")
                    self.assertEqual(value.text, expected)
                    # Keyboard activation exercises the same copy handler as pointer input.
                    button.send_keys(Keys.ENTER)
                    wait.until(lambda _: button.text == "Copied")
                    self.assertEqual(driver.find_element(By.ID, "copy-announcement").text, "Copied")
                    copied = driver.execute_async_script(
                        "const done = arguments[0]; navigator.clipboard.readText().then(done, e => done(String(e)));"
                    )
                    self.assertEqual(copied, expected)
                    self.assertTrue(driver.execute_script(
                        "return arguments[0].scrollWidth <= arguments[0].clientWidth + 1", value
                    ))
                    self.assertNotEqual(driver.execute_script(
                        "return getComputedStyle(arguments[0]).outlineStyle", button
                    ), "none")
                self.assertTrue(driver.execute_script(
                    "return document.documentElement.scrollWidth <= window.innerWidth"
                ))
                driver.find_element(By.ID, "connection-heading").location_once_scrolled_into_view
                screenshot_dir = os.environ.get("POCKET_OID_SELENIUM_SCREENSHOT_DIR")
                if screenshot_dir:
                    output = Path(screenshot_dir)
                    output.mkdir(parents=True, exist_ok=True)
                    driver.save_screenshot(str(output / f"connection-details-{name}.png"))

        # Force a clipboard error and verify that the existing fallback selects the full URL.
        driver.execute_script(
            "Object.defineProperty(navigator.clipboard, 'writeText', {value: () => Promise.reject(new Error('denied'))});"
        )
        button = driver.find_element(By.CSS_SELECTOR, 'button[aria-label="Copy Discovery URL"]')
        button.click()
        wait.until(lambda _: button.text == "Select text to copy")
        self.assertEqual(driver.execute_script("return window.getSelection().toString()"), urls["Discovery URL"])
        self.assertEqual(driver.find_element(By.ID, "copy-announcement").text, "Select text to copy")

    def _open_admin_lists(self, sqlite=True):
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        server = ServerProcess("config-basic")
        self.addCleanup(server.stop)
        server.configure_config = lambda root: _configure_admin_lists(
            root, "list-admin", server.base_url, sqlite=sqlite
        )
        server.start()
        driver = _create_selenium_driver(self.webdriver)
        self.addCleanup(driver.quit)
        driver.set_page_load_timeout(self.timeout)
        driver.get(f"{server.base_url}/admin/login")
        driver.find_element(By.NAME, "username").send_keys("list-admin")
        driver.find_element(By.NAME, "password").send_keys("password123")
        driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        WebDriverWait(driver, self.timeout).until(EC.url_contains("/admin/clients"))
        return server, driver

    def test_admin_list_controls_navigation_and_mobile_layout(self):
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import Select, WebDriverWait

        server, driver = self._open_admin_lists()
        wait = WebDriverWait(driver, self.timeout)
        all_clients = ["ALPHA", "alpha", "Beta", "beta", "zebra", "Zulu"]

        def rows(expected, noun):
            wait.until(lambda _: [link.text for link in driver.find_elements(
                By.CSS_SELECTOR, 'tr:not([hidden]) [data-detail-link]'
            ) if link.is_displayed()] == expected)
            count = f"{len(expected)} {noun}{'' if len(expected) == 1 else 's'} found"
            self.assertEqual(driver.find_element(By.CSS_SELECTOR, '[data-count]').text, count)

        def choose(name, value):
            Select(driver.find_element(By.NAME, name)).select_by_value(value)

        def state(**expected):
            params = parse_qs(urlparse(driver.current_url).query)
            for name, value in expected.items():
                self.assertEqual(driver.find_element(By.NAME, name).get_attribute("value"), value)
                default = {"status": "all", "auth": "all", "sort": "asc", "q": ""}[name]
                self.assertEqual(params.get(name, [default]), [value])

        def clear_search():
            driver.find_element(By.CSS_SELECTOR, '.search [data-clear-search]').click()

        def reset():
            driver.find_element(By.CSS_SELECTOR, '.list-controls [data-reset-list]').click()

        def fits():
            self.assertTrue(driver.execute_script(
                "return document.documentElement.scrollWidth <= window.innerWidth"
            ))
            for control in driver.find_elements(By.CSS_SELECTOR, '.list-controls select, .search'):
                self.assertTrue(driver.execute_script(
                    "const r = arguments[0].getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth;",
                    control,
                ))

        for width in (1280, 390):
            with self.subTest(width=width):
                driver.set_window_size(width, 900)
                if driver.capabilities["browserName"] == "chrome":
                    driver.execute_cdp_cmd("Emulation.setDeviceMetricsOverride", {
                        "width": width, "height": 900, "deviceScaleFactor": 1, "mobile": False,
                    })
                driver.get(f"{server.base_url}/admin/clients")
                rows(all_clients, "application")
                fits()
                driver.execute_script("window.listProbe = true")
                choose("status", "enabled")
                choose("auth", "upstream")
                choose("sort", "desc")
                driver.find_element(By.NAME, "q").send_keys("PORTAL")
                rows(["beta", "ALPHA"], "application")
                self.assertTrue(driver.execute_script("return window.listProbe"))
                self.assertEqual(driver.switch_to.active_element.get_attribute("name"), "q")
                self.assertEqual(driver.find_element(By.CSS_SELECTOR, '[data-count]').get_attribute("aria-live"), "polite")
                fits()
                driver.refresh()
                rows(["beta", "ALPHA"], "application")
                state(q="PORTAL", status="enabled", auth="upstream", sort="desc")
                link = driver.find_element(By.CSS_SELECTOR, 'tr:not([hidden]) [data-detail-link]')
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'})", link)
                saved_scroll = driver.execute_script("return window.scrollY")
                link.click()
                wait.until(lambda _: driver.find_elements(By.CSS_SELECTOR, '[data-back-link]'))
                self.assertIn("auth=upstream", driver.current_url)
                driver.find_element(By.CSS_SELECTOR, '[data-back-link]').click()
                rows(["beta", "ALPHA"], "application")
                state(q="PORTAL", status="enabled", auth="upstream", sort="desc")
                self.assertEqual(driver.switch_to.active_element.text, "beta")
                self.assertAlmostEqual(driver.execute_script("return window.scrollY"), saved_scroll, delta=2)
                driver.find_element(By.CSS_SELECTOR, 'tr:not([hidden]) [data-detail-link]').click()
                wait.until(lambda _: driver.find_elements(By.CSS_SELECTOR, '[data-back-link]'))
                driver.back()
                rows(["beta", "ALPHA"], "application")
                state(q="PORTAL", status="enabled", auth="upstream", sort="desc")
                clear_search()
                rows(["Zulu", "beta", "ALPHA"], "application")
                state(q="", status="enabled", auth="upstream", sort="desc")
                driver.find_element(By.NAME, "q").send_keys("absent")
                rows([], "application")
                self.assertTrue(driver.find_element(By.CSS_SELECTOR, '[data-no-results]').is_displayed())
                reset()
                rows(all_clients, "application")
                state(q="", status="all", auth="all", sort="asc")

                driver.get(f"{server.base_url}/admin/users")
                self.assertFalse(driver.find_elements(By.NAME, "auth"))
                rows(["ALICE", "alice", "Bob", "zebra"], "user")
                choose("status", "disabled")
                choose("sort", "desc")
                driver.find_element(By.NAME, "q").send_keys("USER")
                rows(["zebra", "alice"], "user")
                fits()
                driver.find_element(By.CSS_SELECTOR, 'tr:not([hidden]) [data-detail-link]').click()
                wait.until(lambda _: driver.find_elements(By.CSS_SELECTOR, '[data-close-user]'))
                driver.refresh()
                self.assertEqual(driver.find_element(By.CSS_SELECTOR, '.user-detail h2').text, "zebra")
                state(q="USER", status="disabled", sort="desc")
                fits()
                choose("sort", "asc")
                driver.find_element(By.CSS_SELECTOR, '[data-close-user]').click()
                rows(["alice", "zebra"], "user")
                state(q="USER", status="disabled", sort="asc")
                self.assertEqual(driver.switch_to.active_element.text, "zebra")
                choose("sort", "desc")
                driver.find_element(By.CSS_SELECTOR, 'tr:not([hidden]) [data-detail-link]').click()
                wait.until(lambda _: driver.find_elements(By.CSS_SELECTOR, '[data-close-user]'))
                choose("status", "enabled")
                rows(["Bob", "ALICE"], "user")
                self.assertFalse(driver.find_elements(By.CSS_SELECTOR, '.user-detail'))
                self.assertNotIn("id", parse_qs(urlparse(driver.current_url).query))
                self.assertIn("SQLite", driver.find_element(By.CSS_SELECTOR, '.source').text)
                clear_search()
                state(q="", status="enabled", sort="desc")
                driver.find_element(By.CSS_SELECTOR, 'tr:not([hidden]) [data-detail-link]').click()
                wait.until(lambda _: driver.find_elements(By.CSS_SELECTOR, '[data-close-user]'))
                driver.find_element(By.NAME, "q").send_keys("absent")
                rows([], "user")
                self.assertFalse(driver.find_elements(By.CSS_SELECTOR, '.user-detail'))
                self.assertNotIn("id", parse_qs(urlparse(driver.current_url).query))
                self.assertIn("SQLite", driver.find_element(By.CSS_SELECTOR, '.source').text)
                reset()
                rows(["ALICE", "alice", "Bob", "zebra"], "user")
                state(q="", status="all", sort="asc")
                fits()

    def test_admin_json_disabled_and_native_get_forms(self):
        if os.environ.get("POCKET_OID_SELENIUM_BROWSER", "chrome").lower() != "chrome":
            self.skipTest("disabling JavaScript for native GET forms requires Chrome")
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import Select, WebDriverWait

        server, driver = self._open_admin_lists(sqlite=False)
        wait = WebDriverWait(driver, self.timeout)

        def navigate_click(selector):
            previous = driver.find_element(By.TAG_NAME, "html")
            driver.find_element(By.CSS_SELECTOR, selector).click()
            wait.until(EC.staleness_of(previous))
            wait.until(EC.presence_of_element_located((By.NAME, "q")))
        driver.get(f"{server.base_url}/admin/users")
        Select(driver.find_element(By.NAME, "status")).select_by_value("disabled")
        self.assertEqual(driver.find_element(By.CSS_SELECTOR, '[data-count]').text, "0 users found")
        self.assertTrue(driver.find_element(By.CSS_SELECTOR, '[data-no-results]').is_displayed())
        self.assertIn("JSON", driver.find_element(By.CSS_SELECTOR, '.source').text)
        driver.refresh()
        self.assertEqual(driver.find_element(By.CSS_SELECTOR, '[data-count]').text, "0 users found")

        driver.execute_cdp_cmd("Emulation.setScriptExecutionDisabled", {"value": True})
        self.addCleanup(lambda: driver.execute_cdp_cmd("Emulation.setScriptExecutionDisabled", {"value": False}))
        for section, search, expected in [("clients", "PORTAL", ["beta", "ALPHA"]),
                                          ("users", "ALICE", ["alice", "ALICE"])]:
            driver.get(f"{server.base_url}/admin/{section}?status=invalid&sort=invalid&auth=invalid")
            self.assertEqual(Select(driver.find_element(By.NAME, "status")).first_selected_option.get_attribute("value"), "all")
            self.assertEqual(Select(driver.find_element(By.NAME, "sort")).first_selected_option.get_attribute("value"), "asc")
            driver.find_element(By.NAME, "q").send_keys(search)
            Select(driver.find_element(By.NAME, "status")).select_by_value("enabled")
            Select(driver.find_element(By.NAME, "sort")).select_by_value("desc")
            if section == "clients":
                Select(driver.find_element(By.NAME, "auth")).select_by_value("upstream")
            navigate_click('.list-controls button[type=submit]')
            self.assertEqual([link.text for link in driver.find_elements(
                By.CSS_SELECTOR, 'tr:not([hidden]) [data-detail-link]'
            )], expected)
            navigate_click('.search [data-clear-search]')
            self.assertNotIn("q", parse_qs(urlparse(driver.current_url).query))
            self.assertEqual(Select(driver.find_element(By.NAME, "sort")).first_selected_option.get_attribute("value"), "desc")
            navigate_click('.list-controls [data-reset-list]')
            self.assertFalse(urlparse(driver.current_url).query)

        driver.get(f"{server.base_url}/admin/users?id=user-1")
        Select(driver.find_element(By.NAME, "status")).select_by_value("disabled")
        navigate_click('.list-controls button[type=submit]')
        self.assertNotIn("id", parse_qs(urlparse(driver.current_url).query))
        self.assertFalse(driver.find_elements(By.CSS_SELECTOR, '.user-detail'))
        self.assertEqual(driver.find_element(By.CSS_SELECTOR, '[data-count]').text, "0 users found")

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
