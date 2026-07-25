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
