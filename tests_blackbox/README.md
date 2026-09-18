# Black-box tests

The standard black-box suite uses Python's standard library:

```sh
python3 -m unittest tests_blackbox.test_server_blackbox -v
```

Run discovery across all modules with:

```sh
python3 -m unittest discover -s tests_blackbox -v
```

The Selenium, manual-browser, and OAuth2 Proxy tests remain skipped during
discovery unless their opt-in environment variables are set.

GitHub Actions runs the discovery command above after the Rust build and test
suite. CI explicitly disables all external-service and browser opt-in flags, so
it needs only Python 3 and the Rust toolchain; browser drivers, Selenium,
Keycloak, and OAuth2 Proxy are not installed or run.

## Retaining Pocket-OID logs

Set `POCKET_OID_TEST_LOG_DIR` to add `log_dir` to each server's temporary
`provider.json`:

```sh
POCKET_OID_TEST_LOG_DIR=target/blackbox-logs \
  python3 -m unittest discover -s tests_blackbox -v
```

The directory is created automatically, relative to your current working
directory. Pocket-OID creates a uniquely named, plain-text `.log` file for each
server process. The files remain after tests finish and later runs do not
overwrite them. This also works with the Selenium and manual tests, including
both Pocket-OID servers in the manual re-auth flow. Keycloak logs are not
included. Unset the variable (or leave it empty) to discard server output as
usual. Use `RUST_LOG=debug` alongside it for more verbose Pocket-OID logs.

## Selenium tests

The Selenium authorization-code tests are opt-in. Install Selenium and the
PyJWT cryptography dependencies used to verify signatures:

```sh
python3 -m pip install -r tests_blackbox/requirements-selenium.txt
```

Then run only the Selenium tests:

```sh
POCKET_OID_SELENIUM_CODE_FLOW=1 python3 -m unittest -v \
  tests_blackbox.test_server_selenium
```

The suite also exercises an administrator changing their own password through
the WebUI, including mismatched-confirmation feedback, cleared password fields,
sign-out after success, rejection of the old password, and acceptance of the new
password. It creates a temporary administrator database and never touches a real
administrator account. Run only that coverage with:

```sh
POCKET_OID_SELENIUM_CODE_FLOW=1 python3 -m unittest -v \
  tests_blackbox.test_server_selenium.SeleniumBlackBoxTests.test_administrator_changes_password_in_web_console
```

The Provider settings test checks all four connection URLs against live discovery
metadata, keyboard copying into the real clipboard, accessible feedback, and the
clipboard-failure text-selection fallback. It checks desktop and 390-pixel-wide
layouts using a temporary administrator database. Chrome is required for its
clipboard permission control. Use the repository virtual environment if installed:

```sh
POCKET_OID_SELENIUM_CODE_FLOW=1 .venv/bin/python -m unittest -v \
  tests_blackbox.test_server_selenium.SeleniumBlackBoxTests.test_provider_connection_details_copy_in_desktop_and_narrow_viewports
```

Set `POCKET_OID_SELENIUM_SCREENSHOT_DIR=target/selenium-screenshots` to save its
desktop and narrow viewport screenshots.

The admin list tests use temporary enabled/disabled SQLite users and clients,
including Local/Upstream clients and mixed-case names. They verify combined
search/filter/sort controls, result counts, Clear search, Reset, refresh,
detail/back navigation, inspector dismissal, and desktop/mobile layout. A second
Chrome test covers JSON's all-enabled behavior and native GET forms with
JavaScript disabled:

```sh
POCKET_OID_SELENIUM_CODE_FLOW=1 .venv/bin/python -m unittest -v \
  tests_blackbox.test_server_selenium.SeleniumBlackBoxTests.test_admin_list_controls_navigation_and_mobile_layout \
  tests_blackbox.test_server_selenium.SeleniumBlackBoxTests.test_admin_json_disabled_and_native_get_forms
```

The three-client test starts one Pocket-OID server with these temporary clients:

| Client ID | Signing algorithm | Key fixture |
| --- | --- | --- |
| `selenium-rs256` | RS256 | `config-basic/keys/signing-key.pem` |
| `selenium-es256` | ES256 | `keys/es256.pem` |
| `selenium-ps256` | PS256 | `keys/rsa-alternate.pem` |

Each client has its own test secret and callback URI. Selenium performs a fresh
login as `alice` and approves consent for each client. The test exchanges each
authorization code using that client's credentials, then verifies both access
and ID tokens against the server's JWKS with the expected algorithm. It also
checks issuer, audience, expiration, subject, ID-token nonce, discovery algorithms,
and distinct signing-key IDs. Fixtures and live configuration are not modified.

Run just this test with:

```sh
POCKET_OID_SELENIUM_CODE_FLOW=1 python3 -m unittest -v \
  tests_blackbox.test_server_selenium.SeleniumBlackBoxTests.test_three_clients_use_different_signing_algorithms_in_selenium
```

Chrome runs headlessly by default. Select another supported browser with
`POCKET_OID_SELENIUM_BROWSER=firefox` or `POCKET_OID_SELENIUM_BROWSER=safari`.
Safari also requires `POCKET_OID_SELENIUM_HEADLESS=0` and WebDriver automation
to be enabled with `safaridriver --enable`.

## Five concurrent user sessions

The concurrent Selenium test uses one client (`svc-a`) and five temporary users:
`alice`, `bob`, `carol`, `dave`, and `eve`. Each user has a distinct password,
an isolated WebDriver browser session, and a separate callback with its own state
and nonce. All five browsers submit login together, then wait until everyone has
reached consent before approving together. Login and token exchange run in five
worker threads against the same Pocket-OID server.

The test verifies five distinct session cookies and checks both tokens for each
user: RS256 signature against JWKS, issuer, audience, expiration, expected subject,
and ID-token nonce. This exercises overlapping sessions and identity isolation;
it is not a throughput benchmark.

Run it with Chrome (headless by default):

```sh
POCKET_OID_SELENIUM_CODE_FLOW=1 POCKET_OID_SELENIUM_BROWSER=chrome python3 -m unittest -v \
  tests_blackbox.test_server_selenium.SeleniumBlackBoxTests.test_five_users_log_in_concurrently_in_selenium
```

Firefox is also supported. This test is skipped when Safari is selected. It
starts five browser instances, so allow sufficient memory. Set
`POCKET_OID_SELENIUM_TIMEOUT_SECONDS` above its default of `30` on slower machines.

## Manual re-auth browser flow

The manual re-auth test starts two local Pocket-OID instances: a downstream
provider and an upstream provider. The upstream login page has a purple
background so it is easy to distinguish from the downstream provider.

Run it with:

```sh
POCKET_OID_MANUAL_REAUTH=1 python3 -m unittest -v \
  tests_blackbox.test_server_blackbox.BlackBoxTests.test_manual_reauth_flow_in_browser
```

The test opens the downstream authorization URL. Log in to **Manual Upstream
Pocket-OID** as `alice` with password `password123`, then approve the
downstream consent screen. The test verifies the downstream ID token has the
provider-prefixed subject `manual-upstream:user-alice`.

## Manual Keycloak re-auth flow

The Keycloak test uses the pinned standalone distribution from
`tools/keycloak/VERSION`. Its opt-in test command invokes
`tools/keycloak/ensure-keycloak.sh`, which downloads the distribution only if
it is not already present. A Java runtime compatible with that Keycloak version
must be installed.

Run it with:

```sh
POCKET_OID_MANUAL_KEYCLOAK_REAUTH=1 python3 -m unittest -v \
  tests_blackbox.test_keycloak_reauth_blackbox.KeycloakReauthBlackBoxTests.test_manual_reauth_flow_with_keycloak_upstream
```

The test starts a fresh, temporary Keycloak instance and configures its test
client with that run's exact Pocket-OID callback URI. Log in to the Keycloak
realm as `keycloak-alice` with password `keycloak-password`. This test configures
the temporary downstream client to skip Pocket-OID consent. The downstream ID token must have the subject
`keycloak-local:ff32a9de-d7f1-4dcd-bd4a-2c5ff1c5bdee`.

## Pocket-OID as the provider for OAuth2 Proxy

This automated interoperability test runs three loopback services: Pocket-OID
as the OpenID Connect provider, a real OAuth2 Proxy process as the OIDC client,
and a small protected HTTP application behind the proxy. Python's standard
library submits the login and consent forms; no browser, Selenium, Docker, or
Java is required.

```sh
POCKET_OID_OAUTH2_PROXY=1 python3 -m unittest -v \
  tests_blackbox.test_oauth2_proxy_blackbox
```

The first opt-in run downloads the release pinned in
`tools/oauth2-proxy/VERSION`, verifies the archive against the release's SHA-256
checksum, and caches the executable under `tools/oauth2-proxy/dist/` (ignored by
Git). The helper supports macOS and Linux on ARM64 and AMD64 and requires `curl`,
`tar`, and either `sha256sum` or `shasum`. Later runs reuse the cached executable.
All runtime configuration and sessions are temporary; the test stops its three
services on completion or failure. Proxy diagnostics are included when startup
or callback processing fails.

The test checks that anonymous requests are denied, discovery redirects to
Pocket-OID, the authorization request uses S256 PKCE and a nonce, and login plus
consent returns to the proxy. OAuth2 Proxy exchanges the code and validates the
ID token using Pocket-OID's discovered JWKS, issuer, audience, and nonce. The
protected app must receive the expected subject, and the proxy session must work
on subsequent requests. Removing cookies denies access again, even with spoofed
identity headers.

Pocket-OID currently emits only core ID-token claims, with no `email`,
`email_verified`, or UserInfo endpoint. This test therefore requests `openid`,
uses `--oidc-email-claim=sub` to populate OAuth2 Proxy's required email field with
the subject, and disables fetching additional profile claims. The forwarded
email field is **a subject identifier, not an email address**. This tests core
OIDC interoperability, not email/domain authorization, profile claims, refresh
tokens, or logout. The proxy accepts all email domains for this fixture;
cryptographic validation, issuer/audience validation, nonce validation, and
Pocket-OID's PKCE requirement remain enabled. Insecure cookies are limited to
this local HTTP setup.

See [OAuth2 Proxy configuration](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/)
for the claim-mapping and OIDC options.
