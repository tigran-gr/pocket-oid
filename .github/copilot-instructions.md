# Shared Agent Instructions

This file provides repository guidance for Copilot and agents directed here by
the root `AGENTS.md`.

Pocket-OID is a single-crate Rust OpenID Connect provider built with Axum and
Tokio. It supports client credentials, authorization-code authentication with
server-rendered login and consent pages, and re-authentication through trusted
upstream OIDC providers. It issues RS256-signed JWTs and exposes discovery,
JWKS, health, and readiness endpoints.

Use this guide for orientation and working conventions. Verify implementation
details against current code and tests, and update stale guidance when behavior
changes.

## Documentation and architecture

- [README.md](../README.md): running the service, configuration, login background
  customization, and endpoint usage.
- [Black-box test guide](../tests_blackbox/README.md): automated and opt-in
  browser tests, commands, and prerequisites.
- [Re-auth plan](../plans/re-auth-client-type-plan.md): settled product decisions
  and design context. Plans also contain future proposals; confirm whether a
  feature exists in code before treating a proposal as implemented.

Source layout:

- `Cargo.toml`: Rust edition and dependency declarations.
- `src/main.rs`: CLI help/version, tracing, configuration selection, and listener.
- `src/app.rs`: shared application state, startup wiring, routes, and discovery.
- `src/config.rs`: config loading, schema and semantic validation, local users,
  registered clients, and trusted providers.
- `src/handlers.rs`: token exchange, authorization, local login/consent,
  re-auth callback/consent, and metadata/health handlers.
- `src/auth.rs`: in-memory sessions, authorization codes, and pending re-auth
  and consent transactions. This state is lost on process restart.
- `src/upstream.rs`: OIDC discovery, upstream authorization URLs, code exchange,
  and ID-token validation against upstream JWKS.
- `src/frontend.rs`: server-rendered login and consent HTML.
- `src/token.rs`: access-token template substitution and required claims.
- `src/crypto.rs`: RSA signing-key loading, `kid`, and public JWKS material.
- `src/error.rs`: application and API errors.

## Toolchain and running the service

Run commands from the repository root. Use the installed Rust toolchain; there
is currently no `rust-toolchain.toml`. Python tests use Python 3 and `unittest`.
Use `cargo build --release` when a release binary is needed. Reserve
`cargo clean` for troubleshooting that requires rebuilding cached artifacts.

Start the development configuration with `cargo run --quiet`. It uses `./config`
relative to the working directory and listens on `127.0.0.1:8080` with the
checked-in settings. Check readiness at `/readyz`. For CLI help, use
`cargo run -- --help`.

Select another configuration with:

```sh
POCKET_OID_CONFIG_DIR=tests/fixtures/config-basic cargo run --quiet
```

The server is a long-lived process; stop any instances started for verification.
A bind failure may mean the configured port is already occupied.

## Runtime configuration

A configuration directory must contain:

- `provider.json`
- `clients.json`
- `users.json`
- `token_template.json`
- `keys/signing-key.pem`

The loader requires at least one enabled client and at least one local user,
including for setups that use only re-auth clients. `trusted_providers.json` is
optional when no re-auth clients are configured. Every re-auth client must
reference a provider defined in that file and include `openid` in its upstream
scopes. Provider credentials belong in the trusted-provider definition.

Client authentication and consent settings:

| Setting | Values and behavior |
| --- | --- |
| `auth_mode` | `local` (default) or `re_auth`; selects the authentication flow. |
| `consent_mode` | `always` (default) or `skip`; controls local-authentication consent. |
| `re_auth.consent` | `local` (default) or `skip`; controls consent after upstream authentication. |

A local client must not define `re_auth`. A re-auth client must define it;
its consent behavior is controlled by `re_auth.consent`, not `consent_mode`.
Keep `token_template.json`'s `iss` aligned with the configured provider issuer.
The checked-in credentials and signing keys are development fixtures.

Invalid configuration intentionally fails at startup. The fixture
`tests/fixtures/config-invalid-clients/` exercises this behavior; use
`tests/fixtures/config-basic/` as the base for valid test configurations.

## Re-auth decisions to preserve

- Authentication routing and consent policy come from registered client
  configuration. An `/authorize` query parameter cannot override `auth_mode`.
- Resolve upstream endpoints through the issuer's
  `/.well-known/openid-configuration`; require the discovered issuer to match
  the configured issuer exactly.
- Validate upstream state, nonce, signature, issuer, audience, and token timing
  before issuing a downstream code. Preserve PKCE checks, expiration, and the
  single-use, provider-bound pending transaction behavior.
- Map the validated upstream subject to `{provider_id}:{upstream_sub}`.
  Pocket-OID issues its own downstream codes and tokens.
- Do not embed upstream token strings or entire upstream token payloads in
  downstream tokens. Claim propagation and refresh-token support remain deferred.
- Re-auth uses local consent by default. The Keycloak manual test explicitly
  sets `re_auth.consent: "skip"` in its temporary client configuration; the
  Pocket-OID-to-Pocket-OID manual test exercises local consent.

## Verification

For Rust code changes, run:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Unit tests live alongside source modules. Integration tests under
`tests/integration/` cover metadata, health, tokens, authorization codes, PKCE,
consent, and re-auth. Shared Rust helpers live in `tests/common/mod.rs`.

For Python test-harness changes or changes affecting process startup and HTTP
flows, run the ordinary black-box suite using `unittest`:

```sh
python3 -m unittest discover -s tests_blackbox -v
```

Run ordinary discovery with the browser opt-in flags unset. Selenium and manual
tests are skipped by default; ordinary tests use Python's standard library.
The shared `tests_blackbox/blackbox_support.py` creates temporary fixture copies,
allocates loopback ports, starts processes, and handles callback token exchange.
Use these helpers when extending the tests.

Loopback restrictions affect coverage: Python tests can fail with
`PermissionError`, and the Rust mock-provider helper in
`tests/integration/reauth.rs` returns early if binding is denied. Some code-flow
tests also fall back to in-process dispatch. A green run in a restricted sandbox
does not prove that live HTTP paths ran. For changes to those paths, verify in
an environment that permits loopback listeners and report any coverage gaps.

For documentation-only or ignore-rule changes, check links, paths, examples,
or ignore behavior as appropriate and run `git diff --check`; a full runtime
suite is unnecessary. Report which checks ran and which were skipped.

## Browser tests and Keycloak

Use the [black-box test guide](../tests_blackbox/README.md) for browser commands.
Opt-in flags select distinct tests:

- `POCKET_OID_MANUAL_CODE_FLOW=1`: manual local authorization-code flow.
- `POCKET_OID_MANUAL_REAUTH=1`: manual flow with another Pocket-OID upstream.
- `POCKET_OID_MANUAL_KEYCLOAK_REAUTH=1`: manual flow with a Keycloak upstream.
- `POCKET_OID_SELENIUM_CODE_FLOW=1`: automated browser flow; requires the
  dependencies in `tests_blackbox/requirements-selenium.txt` and a browser.

Manual tests open a browser and wait for user interaction. Keycloak additionally
requires a compatible Java runtime on `PATH`. Its pinned distribution version
comes from `tools/keycloak/VERSION`; `tools/keycloak/ensure-keycloak.sh` downloads
it only when missing. Downloaded archives and distributions are ignored by Git;
the helper, version file, and realm fixture belong in the repository.

`KeycloakProcess` runs a fresh temporary copy, imports the realm, and registers
the exact callback URI allocated for that test. Keep runtime state in that
temporary copy. Keycloak import filenames must match `<realm>-realm.json`;
the helper derives that runtime filename from the realm name.

## UI design notes

Keep login and consent pages minimal, accessible, and responsive. Preserve
the white login panel, teal accents, clear labels, error messages, and configured
`login_background_color` behavior. Preserve form routes, hidden `return_to`,
username/password autocomplete, and server-side re-auth consent transaction IDs.
