# Pocket-OID Integration Testing Plan

## 1. Goals
- Add repeatable integration tests that validate Pocket-OID behavior at the HTTP API boundary (not just internal handler logic).
- Ensure token issuance, OIDC metadata, and JWKS behavior remain correct under realistic conditions.
- Keep local developer workflow fast while enabling CI-grade confidence.

## 2. Current Baseline (what exists today)
- The project already has async endpoint tests in `src/handlers.rs` that exercise router paths in-process via `tower::ServiceExt::oneshot`.
- These tests provide strong request/response coverage, but they are tightly coupled to internal Rust modules and do not validate the binary as a running process.

## 3. Recommended Strategy (hybrid)
Use a **two-layer integration strategy**:

1. **Primary: Rust integration tests (`tests/` directory)**
   - Best for speed, maintainability, and direct access to project types.
   - Should test the full Axum router with realistic HTTP form payloads and response validation.
   - Keep these as the default test suite run in `cargo test`.

2. **Secondary: Python black-box smoke tests (optional but recommended)**
   - Use Python to launch the compiled server binary and hit real localhost endpoints with `requests`.
   - Valuable as process-level verification independent of Rust internals.
   - Run as a separate command (e.g., `python -m pytest tests_blackbox`) in CI or pre-release checks.

This approach gives confidence at both app-internal and process-external boundaries without making routine development slow.

## 4. Test Scope and Matrix

### 4.1 Core scenarios to cover
- `GET /.well-known/openid-configuration` returns expected issuer, token endpoint, and JWKS URI.
- `GET /jwks.json` returns at least one key with required RSA fields (`kid`, `kty`, `alg`, `n`, `e`).
- `POST /oauth/token` with valid client credentials returns `200` and a usable Bearer token.
- Unsupported `grant_type` returns OAuth-compliant error (`unsupported_grant_type`).
- Invalid credentials return OAuth-compliant auth failure (`invalid_client`).
- Invalid scope requests return OAuth-compliant validation failure (`invalid_scope`).
- Health/readiness endpoints return successful status.

### 4.2 Token validation assertions
- Decode returned JWT using JWKS key selected by `kid`.
- Verify signature, issuer, audience, expiration, and subject.
- Validate template-driven custom claims expected from fixture config.

### 4.3 Robustness scenarios
- Parallel token requests produce independent valid responses.
- Missing required form fields produce clear RFC-compliant errors.
- Configuration load failure is observable at startup (black-box test: non-zero process exit).

## 5. Rust Integration Test Design

## 5.1 Project structure
Create a dedicated structure:

- `tests/integration/metadata.rs`
- `tests/integration/token_success.rs`
- `tests/integration/token_errors.rs`
- `tests/integration/health.rs`
- `tests/common/mod.rs` (test fixture helpers)

### 5.2 Common helper responsibilities (`tests/common/mod.rs`)
- Build/initialize `AppState` from a fixture config path.
- Provide helper for form-encoded token requests.
- Provide JWT verification helper that:
  - fetches discovery document,
  - resolves JWKS URI,
  - selects key by `kid`,
  - validates token claims.

### 5.3 Fixture strategy
- Keep a stable fixture directory (e.g., `tests/fixtures/config-basic/`) containing:
  - `provider.json`,
  - `clients.json`,
  - `token_template.json`,
  - signing key pair.
- Use deterministic fixture data for predictable assertions.
- Add a second fixture for negative startup tests (e.g., malformed client schema).

### 5.4 Execution model
- Prefer in-process router integration with `oneshot` for speed.
- Use `tokio::test` and avoid global mutable state.
- Keep tests deterministic and independent (no port binding needed at this layer).

## 6. Python Black-Box Test Design (Optional Layer)

### 6.1 When to use Python here
Python is useful when validating behavior from outside the Rust runtime:
- process startup/shutdown,
- environment variable wiring (`POCKET_OID_CONFIG_DIR`),
- TCP listener behavior,
- end-to-end HTTP client interactions.

### 6.2 Suggested stack
- `pytest`
- `requests`
- `python-jose` or `pyjwt` (token decode/verify)
- `tenacity` (optional retry/wait for startup)

### 6.3 Suggested layout
- `tests_blackbox/test_server_startup.py`
- `tests_blackbox/test_token_flow.py`
- `tests_blackbox/conftest.py` (server process fixture + teardown)

### 6.4 Process fixture behavior
- Start binary (`cargo run --quiet` or built artifact) with fixture config env var.
- Wait until `/readyz` returns success.
- Run tests against `http://127.0.0.1:<port>`.
- Ensure cleanup by terminating process after tests.

## 7. CI Pipeline Proposal

## 7.1 Fast default CI
1. `cargo fmt -- --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test`

### 7.2 Extended CI (nightly or gated)
4. Build binary once: `cargo build --release`
5. Run Python black-box suite against built artifact.

This split keeps pull request feedback quick while still validating real-process behavior regularly.

## 8. Migration Plan (incremental implementation)

### Phase 1: Consolidate Rust integration structure
- Move/replicate current endpoint behavior tests into `tests/integration/*`.
- Introduce shared helpers and fixture directories.
- Keep existing tests temporarily to avoid regression risk.

### Phase 2: Expand negative-path coverage
- Add exhaustive OAuth error-path tests.
- Add edge-case scope and malformed form-body checks.

### Phase 3: Add Python smoke tests
- Implement 2–3 high-value black-box scenarios:
  1. startup + readiness,
  2. successful token flow,
  3. startup failure with invalid config.

### Phase 4: CI integration
- Add Python test job as optional/extended stage.
- Promote to required once stable.

## 9. Practical Recommendation (what I would do first)
If only one path is chosen now, prioritize **Rust integration tests in `tests/`** first:
- lower maintenance overhead,
- no extra runtime dependency chain,
- best developer ergonomics.

Then add Python smoke tests later as a release-confidence layer.

## 10. Definition of Done
- Integration tests live under dedicated `tests/` structure with common fixtures.
- Success + error-path OAuth scenarios are covered.
- JWT verification is performed using JWKS-derived keys.
- CI executes integration tests on every PR.
- Optional Python black-box tests are documented and runnable.

## 11. Risks and mitigations
- **Risk:** test flakiness from time-based claims (`iat`, `exp`).
  - **Mitigation:** assert ranges with small leeway rather than exact timestamps.
- **Risk:** key fixture rotation breaks assertions.
  - **Mitigation:** verify semantics (`kid` match + successful signature validation), not hard-coded full token values.
- **Risk:** duplicate effort between Rust and Python suites.
  - **Mitigation:** keep Python suite minimal and smoke-focused.

## 12. Deliverables checklist
- [ ] `tests/integration/*` modules and `tests/common/mod.rs` helpers.
- [ ] `tests/fixtures/*` config and key material.
- [ ] Coverage for positive and negative token endpoint flows.
- [ ] Discovery + JWKS integration tests.
- [ ] (Optional) `tests_blackbox/*` Python smoke tests.
- [ ] CI updates and developer docs.
