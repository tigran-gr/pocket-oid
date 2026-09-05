# Black-box browser tests

The standard black-box suite uses Python's standard library:

```sh
python3 -m unittest tests_blackbox.test_server_blackbox -v
```

Run discovery across both modules with:

```sh
python3 -m unittest discover -s tests_blackbox -v
```

The Selenium and manual-browser tests remain skipped during discovery unless
their opt-in environment variables are set.

The Selenium authorization-code test is opt-in. Install its dependency:

```sh
python3 -m pip install -r tests_blackbox/requirements-selenium.txt
```

Then run only the Selenium test:

```sh
POCKET_OID_SELENIUM_CODE_FLOW=1 python3 -m unittest -v \
  tests_blackbox.test_server_selenium
```

Chrome runs headlessly by default. Select another supported browser with
`POCKET_OID_SELENIUM_BROWSER=firefox` or `POCKET_OID_SELENIUM_BROWSER=safari`.
Safari also requires `POCKET_OID_SELENIUM_HEADLESS=0` and WebDriver automation
to be enabled with `safaridriver --enable`.

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
