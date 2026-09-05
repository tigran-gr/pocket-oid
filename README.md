# pocket-oid

`pocket-oid` is a small OpenID Connect provider. It issues RS256-signed JWTs
for the client-credentials and authorization-code flows and exposes discovery,
JWKS, health, and readiness endpoints. It also supports OIDC identity brokering
through its re-authentication (`re_auth`) mode.

## Run it

From the repository root, start the development configuration:

```sh
cargo run --quiet
```

The checked-in configuration listens on `127.0.0.1:8080`. Confirm that the
service is ready with:

```sh
curl http://127.0.0.1:8080/readyz
```

For a compiled binary:

```sh
cargo build --release
./target/release/pocket-oid
```

Use `--help` to view the binary's built-in usage and configuration summary:

```sh
pocket-oid --help
```

`--version` is also supported. The binary has no required positional arguments.

## Configure it

Set `POCKET_OID_CONFIG_DIR` to select a configuration directory. If it is not
set, the binary uses `./config` relative to the current working directory.

```sh
POCKET_OID_CONFIG_DIR=/srv/pocket-oid/config pocket-oid
```

The directory must contain:

```text
provider.json
clients.json
users.json
token_template.json
keys/signing-key.pem
```

`provider.json` defines the provider name, public issuer URL, default token TTL,
and listen address. The issuer should be the externally reachable base URL used
by clients; it is used to construct the discovery and JWKS URLs.

To replace the login screen's default gradient with a solid color, optionally
set `login_background_color` to a hex color in `provider.json`:

```json
"login_background_color": "#1a2b3c"
```

Supported values are `#RGB`, `#RGBA`, `#RRGGBB`, and `#RRGGBBAA`. Omit the
setting (or set it to `null`) to retain the default background.

`clients.json` is an array of OAuth clients. Each client needs `client_id` and
`client_secret`; it may additionally set an audience, allowed scopes, token TTL,
redirect URIs, supported response types, PKCE policy, consent mode, and token
metadata. At least one enabled client is required.

`users.json` contains users for the authorization-code flow. At least one user
is required. Store either a SHA-256 password hash (`password_hash`) or a plain
password (`password_plain`) for each user; use hashes outside local development.

`token_template.json` is the JSON claim template for issued tokens. The supplied
configuration illustrates the supported runtime placeholders. Keep its `iss`
claim aligned with `provider.json`'s issuer.

The checked-in `config/` directory contains development credentials and keys;
replace them before any non-local deployment. Protect the signing key and client
secrets with appropriate filesystem permissions.

## Re-authentication (identity brokering)

Re-auth lets an application use accounts from a trusted upstream OIDC provider,
such as another Pocket-OID instance. The browser signs in at the
upstream provider, then returns to Pocket-OID. Pocket-OID validates the upstream
ID token and issues its own authorization code and tokens for the application.

To enable it, add these fields to the application's registered client entry in
`clients.json`:

```json
{
  "auth_mode": "re_auth",
  "re_auth": {
    "provider_id": "partner-pocket-oid",
    "upstream_scopes": ["openid", "email"],
    "consent": "local"
  }
}
```

Define the matching provider in `trusted_providers.json`, including its issuer,
upstream client credentials, and Pocket-OID callback URI:
`https://<pocket-oid-host>/reauth/callback/partner-pocket-oid`. Register that exact
callback URI with the upstream provider. Pocket-OID discovers upstream endpoints
through the issuer's `/.well-known/openid-configuration`. See the
[re-auth configuration example](plans/re-auth-client-type-plan.md#3-configuration-model)
for the complete client and provider entries.

Local consent is shown by default; `re_auth.consent: "skip"` omits that screen.
This setting is separate from `consent_mode`, which controls consent for local
authentication. Clients without `auth_mode` continue to use local authentication;
the browser cannot override the registered authentication mode.

The resulting subject is `{provider_id}:{upstream_sub}`, for example
`partner-pocket-oid:user-123`. Upstream tokens and their entire payloads are not
embedded in downstream tokens, and upstream claim propagation and refresh tokens
are not currently supported. The configuration loader still requires `users.json`
with at least one local user, even when all clients use re-auth.

Try the [manual browser test with a Pocket-OID upstream](tests_blackbox/README.md#manual-re-auth-browser-flow).

## Endpoints

With the default listener, the service provides:

- `GET /.well-known/openid-configuration` — OpenID discovery metadata
- `GET /jwks.json` — public signing keys
- `POST /oauth/token` — token exchange
- `GET /authorize`, `POST /login`, `POST /consent` — authorization-code flow
- `GET /reauth/callback/:provider_id` — upstream authorization callback
- `GET /reauth/consent/:transaction_id`, `POST /reauth/consent` — re-auth consent
- `GET /healthz` and `GET /readyz` — health checks

Discovery metadata uses the configured issuer, so a reverse proxy should route
that public URL to this process.

## Logs

Logs go to standard error. Set `RUST_LOG` to control verbosity:

```sh
RUST_LOG=debug pocket-oid
```
