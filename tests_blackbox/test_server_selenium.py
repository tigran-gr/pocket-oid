import os
import time
import unittest

from tests_blackbox.blackbox_support import (
    CodeFlowCallback,
    ServerProcess,
    authorize_path,
    decode_jwt_unverified,
    enable_openid_scope,
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


class SeleniumBlackBoxTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("POCKET_OID_SELENIUM_CODE_FLOW") == "1",
        "set POCKET_OID_SELENIUM_CODE_FLOW=1 to run the Selenium browser code-flow test",
    )
    def test_authorization_code_flow_in_selenium(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait
        except ModuleNotFoundError:
            self.fail(
                "Selenium is not installed; run "
                "'python3 -m pip install -r tests_blackbox/requirements-selenium.txt'"
            )

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
            timeout = int(
                os.environ.get("POCKET_OID_SELENIUM_TIMEOUT_SECONDS", "30")
            )
            driver = _create_selenium_driver(webdriver)
            driver.set_page_load_timeout(timeout)
            wait = WebDriverWait(driver, timeout)

            driver.get(authorize_url)
            wait.until(
                EC.visibility_of_element_located((By.NAME, "username"))
            ).send_keys("alice")
            driver.find_element(By.NAME, "password").send_keys("password123")
            driver.find_element(
                By.CSS_SELECTOR, 'form[action="/login"] button[type="submit"]'
            ).click()

            wait.until(
                EC.element_to_be_clickable(
                    (
                        By.CSS_SELECTOR,
                        'form[action="/consent"] button[value="approve"]',
                    )
                )
            ).click()
            wait.until(
                EC.text_to_be_present_in_element(
                    (By.TAG_NAME, "body"), "Authentication was successful"
                )
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
            try:
                if driver is not None:
                    driver.quit()
            finally:
                callback.stop()
                server.stop()


if __name__ == "__main__":
    unittest.main()
