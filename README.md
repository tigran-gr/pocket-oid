# pocket-oid

`pocket-oid` is a small OpenID Connect provider. It issues RS256-signed JWTs
for the client-credentials and authorization-code flows and exposes discovery,
JWKS, health, and readiness endpoints.

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

## Endpoints

With the default listener, the service provides:

- `GET /.well-known/openid-configuration` — OpenID discovery metadata
- `GET /jwks.json` — public signing keys
- `POST /oauth/token` — token exchange
- `GET /authorize`, `POST /login`, `POST /consent` — authorization-code flow
- `GET /healthz` and `GET /readyz` — health checks

Discovery metadata uses the configured issuer, so a reverse proxy should route
that public URL to this process.

## Logs

Logs go to standard error. Set `RUST_LOG` to control verbosity:

```sh
RUST_LOG=debug pocket-oid
```
