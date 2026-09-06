# pocket-oid

<img src="assets/pocket-oid-logo.svg" alt="Pocket-OID logo: a key tucked into a teal pocket" width="480">

`pocket-oid` is a small OpenID Connect provider. It issues RS256-, ES256-, or PS256-signed JWTs
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

`keys/signing-key.pem` is the default key location; `signing_key_paths` can select
another location as described under [token signing](#token-signing).

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
redirect URIs, supported response types, PKCE policy, consent mode, signing algorithm, and token
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

### Token signing

`provider.json` accepts `signing_algorithm`: `"RS256"` (the default), `"ES256"`, or `"PS256"`.
This is the default for clients that do not specify their own `signing_algorithm`.
The effective client algorithm signs both access tokens and ID tokens, including
tokens issued after re-authentication.

For ES256, set this field in `provider.json`:

```json
"signing_algorithm": "ES256"
```

Generate an unencrypted PKCS#8 PEM private key on the P-256 curve:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es256-key.pem
```

Install that key as `keys/signing-key.pem` in the selected configuration directory
and restart the service. The EC JWK contains `kty: "EC"`, `crv: "P-256"`, and
base64url-encoded `x` and `y` coordinates. ES256 signatures use the standard JWT
64-byte format. Other curves, SEC1 (`EC PRIVATE KEY`) files, and keys that do not
match the configured algorithm are rejected at startup. RS256 continues to use
an unencrypted PKCS#8 RSA private key.

For PS256 (RSA-PSS with SHA-256), set:

```json
"signing_algorithm": "PS256"
```

Use an unencrypted PKCS#8 RSA private key of at least 2048 bits at
`keys/signing-key.pem`; an existing compatible RS256 key can be used. To generate
a new key:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ps256-key.pem
```

Install it as `keys/signing-key.pem` and restart. PS256 publishes an RSA JWK with
`alg: "PS256"`, `n`, and `e`. Keys shorter than 2048 bits are rejected at startup.

#### Client signing overrides

Clients can optionally set `signing_algorithm` in `clients.json` to `"RS256"`,
`"ES256"`, or `"PS256"`. Omit it (or set it to `null`) to inherit the provider
default. For example, these two client entries use different algorithms:

```json
[
  {
    "client_id": "rsa-client",
    "client_secret": "replace-with-rsa-client-secret",
    "signing_algorithm": "RS256"
  },
  {
    "client_id": "pss-client",
    "client_secret": "replace-with-pss-client-secret",
    "signing_algorithm": "PS256"
  }
]
```

Keep the provider's default RSA key in `keys/signing-key.pem`. Generate a separate
RSA key for PS256 with the command above, install it as `keys/ps256.pem`, and add
these fields to the existing `provider.json`:

```json
{
  "signing_algorithm": "RS256",
  "signing_key_paths": {
    "PS256": "keys/ps256.pem"
  }
}
```

`signing_key_paths` maps algorithms to private-key files. Relative paths are
resolved against the configuration directory; absolute paths are also accepted.
The provider default falls back to `keys/signing-key.pem` if it has no map entry.
Every other algorithm requested by an enabled client needs a map entry. Multiple
clients using the same algorithm share its key. To add ES256 clients, provide an
ES256 map entry pointing to a P-256 key.

Different algorithms must use distinct keys. Startup rejects missing or incompatible
keys and reuse of the same key across algorithms. This keeps every `kid` unambiguous
and binds each key to one algorithm, following [JWT best practices](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1).

Discovery advertises the provider default plus overrides used by enabled clients;
JWKS publishes one public key per algorithm. Disabled clients and unused entries
in `signing_key_paths` do not enable or publish additional algorithms. Existing
default-key IDs are preserved. OAuth request parameters cannot override the
registered client's algorithm, and upstream verification policy is independent.

Restart after configuration changes. Old verification keys are not retained when
an algorithm is removed or its key is replaced; coordinate changes with token
consumers and the lifetime of previously issued tokens.

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

Upstream ID tokens use a separate algorithm policy. Each entry in
`trusted_providers.json` can set `allowed_signing_algorithms`, which defaults to
`["RS256"]`. For an ES256 upstream, configure:

```json
"allowed_signing_algorithms": ["ES256"]
```

For a PS256 upstream, use `["PS256"]`. Multiple algorithms can be allowed, for
example `["RS256", "ES256", "PS256"]`. The list must be nonempty and contain only
these supported algorithms. The token's algorithm must be allowed and match
its JWKS key type, curve, and any declared algorithm or verification usage.
RS256 and PS256 are distinct algorithms even though both use RSA keys.
This setting is independent of Pocket-OID's own `signing_algorithm`.

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

By default, logs go to standard error with terminal colors. Set `RUST_LOG` to
control verbosity:

```sh
RUST_LOG=debug pocket-oid
```

To write logs to files instead, set `log_dir` in `provider.json`:

```json
"log_dir": "logs"
```

Relative paths resolve from the configuration directory; absolute paths are
used as written. Pocket-OID creates the directory when needed and writes each
process to a uniquely named, plain-text `.log` file. When `log_dir` is set,
Pocket-OID does not also write logs to standard error.
