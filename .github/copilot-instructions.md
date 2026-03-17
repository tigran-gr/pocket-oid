# Copilot Instructions

Pocket-OID is a small single-crate Rust service that implements a minimal OpenID Connect provider for the client credentials flow only. It serves discovery metadata, JWKS, token issuance, and health/readiness endpoints. The repo is intentionally compact: about 36 tracked source/config files, mostly Rust plus JSON fixtures and one Python smoke test. There is no database, no frontend, no Dockerfile, no Makefile/justfile, and no checked-in GitHub Actions workflow yet.

Trust these instructions first and only search when they are incomplete or proven wrong.

## Toolchain and bootstrap

Validated locally on March 18, 2026:
- `rustc 1.94.0`
- `cargo 1.94.0`
- `python3 3.14.3`

There is no `rust-toolchain.toml`, so use the installed toolchain. `cargo fmt` and `cargo clippy` were available and worked. Always run commands from the repo root.

Cold-start validation from a clean tree was:

```bash
cargo clean
cargo test
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

Observed timings from a cold run:
- `cargo test`: passed in about 18s and is the best bootstrap command because it compiles the crate and runs all Rust tests.
- `cargo fmt -- --check`: passed in under 1s.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed in about 6s.
- `cargo build --release`: passed in about 19s.

Recommended pre-PR sequence:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Always run `cargo test` before assuming a code change is safe; this repo has meaningful in-process coverage.

## Run and runtime config

`cargo run --quiet` starts the server with the checked-in `config/` directory by default. That config binds `127.0.0.1:8080`; `/readyz` returned `200 OK` when validated locally.

Use `POCKET_OID_CONFIG_DIR` to point the binary at another config directory:

```bash
POCKET_OID_CONFIG_DIR=tests/fixtures/config-basic cargo run --quiet
```

That environment variable is the main runtime switch in this repo and is also how the Python black-box test selects alternate configs.

A valid config directory must contain:
- `provider.json`
- `clients.json`
- `token_template.json`
- `keys/signing-key.pem`

Fail-fast startup with invalid config is intentional and already tested. This command exited non-zero in about 0.6s with a schema-validation error:

```bash
env POCKET_OID_CONFIG_DIR=tests/fixtures/config-invalid-clients cargo run --quiet
```

Common failure modes:
- Port `127.0.0.1:8080` may already be in use when you run the default config.
- Live socket tests can fail in restricted sandboxes with `PermissionError: [Errno 1] Operation not permitted` when binding `127.0.0.1`; treat that as an environment restriction before changing code.
- `cargo run --quiet` is a long-lived server process; stop it manually after smoke testing.

## Tests

Rust tests are the default validation layer and should stay green under `cargo test`:
- 3 unit/internal endpoint tests live in `src/handlers.rs`.
- 9 integration tests live under `tests/`.

The process-level smoke test is:

```bash
python3 -m unittest tests_blackbox.test_server_blackbox -v
```

That passed in about 1.3s once localhost binding was allowed. Do not default to `pytest`: the planning doc mentions it, but `pytest` is not installed here and `python3 -m pytest --version` failed with `No module named pytest`. The existing Python test uses only the standard library `unittest`.

## Layout and architecture

Important files to open first:
- `Cargo.toml`: single package `pocket-oid`, Rust edition 2024, Axum/Tokio server.
- `src/main.rs`: process entrypoint, tracing init, reads `POCKET_OID_CONFIG_DIR`, binds the listener.
- `src/app.rs`: `AppState`, startup wiring, router construction, discovery metadata assembly.
- `src/config.rs`: loads `provider.json`, `clients.json`, `token_template.json`; validates client config with `schemars` + `jsonschema`; resolves key paths.
- `src/handlers.rs`: `/oauth/token`, `/.well-known/openid-configuration`, `/jwks.json`, `/healthz`, `/readyz`; client auth and scope validation.
- `src/token.rs`: placeholder substitution for token templates and required claim enforcement.
- `src/crypto.rs`: loads RSA signing key, computes `kid`, exposes JWKS material.
- `src/error.rs`: app and API errors.

Test/layout files:
- `config/`: default runtime config used by `cargo run`.
- `tests/fixtures/config-basic/`: stable valid fixture config.
- `tests/fixtures/config-invalid-clients/`: intentionally invalid startup fixture.
- `tests/common/mod.rs`: shared helpers for integration tests.
- `tests/integration/*.rs`: discovery, health, token success, parallel request, and OAuth error-path coverage.
- `tests_blackbox/test_server_blackbox.py`: launches `cargo run --quiet`, rewrites copied fixture config to a free port, and verifies both successful startup and expected startup failure.

Repository notes that save time:
- `README.md` is only a one-line summary; most useful repo knowledge is in the code.
- `plans/` and `provider-plan.md` are forward-looking planning docs, not the current source of truth. They mention proposed CI and future authorization-code-flow work; do not assume either exists in the current implementation.
- There is currently no `.github/workflows/` directory. Replicate CI locally with the `fmt` + `clippy` + `test` sequence above.
