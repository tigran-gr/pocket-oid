# Black-box tests

The standard black-box suite uses Python's standard library:

```sh
python3 -m unittest tests_blackbox.test_server_blackbox -v
```

Run discovery across all modules with:

```sh
python3 -m unittest discover -s tests_blackbox -v
```

The Selenium and manual-browser tests remain skipped during discovery unless
their opt-in environment variables are set.

GitHub Actions runs the discovery command above after the Rust build and test
suite. CI explicitly disables all Selenium and manual-browser opt-in flags, so
it needs only Python 3 and the Rust toolchain; browser drivers, Selenium, and
Keycloak are not installed or run.

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
