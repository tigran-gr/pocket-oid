# Pocket-OID Implementation Plan

## 1. Goals & Scope
- Deliver a minimal yet standards-compliant OpenID Provider written in Rust.
- Initial release: client credentials flow only; support `.well-known/openid-configuration`, `jwks.json`, and `oauth/token` endpoints.
- Future release: extend to authorization code flow with a Vue.js front end without rewriting the core auth services.

## 2. Functional Requirements
- Accept confidential clients identified by `client_id` + plaintext `client_secret` stored in a local config file.
- Issue signed JWT access tokens derived from a configurable JSON template (per client or global) with placeholder substitution.
- Publish discovery metadata and JSON Web Key Set that match the signing keys used for tokens.
- Reject invalid credentials, malformed requests, unsupported grant types, or inactive clients with spec-compliant error payloads.
- Provide structured logging, simple health metrics, and deterministic startup validation of configuration files.

## 3. Standards & Protocol Coverage
- OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4).
- OpenID Connect Discovery for the `.well-known/openid-configuration` document.
- JSON Web Tokens (RFC 7519) signed with RS256 (default) via JSON Web Signature (RFC 7515).
- JSON Web Key Set format (RFC 7517) for public keys.

## 4. Service Architecture
1. **HTTP Layer**: Axum (or Actix) + Hyper server with Tower middleware for logging, tracing, and error handling.
2. **Config Loader**: Reads `config/clients.json` and `config/token_template.json` at startup; provides hot-reload hook for later.
3. **Credential Store**: In-memory map keyed by `client_id`, storing plaintext secret and metadata.
4. **Key Manager**: Loads RSA/ECDSA private keys from PEM files under `config/keys/`; exposes signing + JWKS serialization.
5. **Token Service**: Builds claims from template, injects request-specific values, signs JWT, and returns response DTO.
6. **Metadata Service**: Generates discovery doc and JWKS outputs on demand backed by cached structs.

## 5. Data & Configuration
- `config/clients.json`: array of clients `{ "client_id": "svc-a", "client_secret": "supersecret", "audience": "https://api" }`.
- `config/token_template.json`: JSON object with placeholders using `${placeholder}` syntax, e.g. `${client_id}`, `${audience}`, `${issued_at}`.
- `config/keys/signing-key.pem`: RSA private key; companion `signing-key.pub` for validation and JWKS generation.
- Use Serde + schemars to validate config structure at boot; fail fast if invalid.

## 6. Access Token Template Strategy
- Load the JSON template as `serde_json::Value`.
- Supported placeholders: `client_id`, `audience`, `scope`, `issued_at`, `expires_at`, `tenant`, and free-form `metadata.*` keys from client config.
- Token generation steps:
  1. Clone template tree.
  2. Walk values replacing strings containing `${...}` with runtime values.
  3. After substitution, ensure required JWT claims exist (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`).
  4. Sign resulting claim set with RS256.
- Example template:
```json
{
  "iss": "https://pocket-oid.local",
  "sub": "${client_id}",
  "aud": "${audience}",
  "scope": "${scope}",
  "iat": "${issued_at}",
  "exp": "${expires_at}",
  "jti": "${uuid}",
  "custom": {
    "tenant": "${metadata.tenant}",
    "env": "dev"
  }
}
```

## 7. HTTP Endpoints
### 7.1 `GET /.well-known/openid-configuration`
- Return issuer URL, token endpoint, supported grant types (`client_credentials`), JWKS URI, signing algorithms, and introspection revocation placeholders.
- Cache response and revalidate when config changes.

### 7.2 `GET /jwks.json`
- Serve public keys derived from loaded signing keys.
- Include `kid`, `kty`, `alg`, `use`, `n`, `e` for RSA.
- Refresh automatically if keys rotate (future enhancement).

### 7.3 `POST /oauth/token`
- Accept `application/x-www-form-urlencoded` body with `grant_type=client_credentials`, `client_id`, `client_secret`, optional `scope`.
- Authenticate client by comparing plaintext secret from config; constant-time compare to reduce timing leaks.
- Response payload:
```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "scopeA scopeB"
}
```
- Error payloads follow RFC 6749 (`invalid_client`, `invalid_grant`, `unsupported_grant_type`).

## 8. Token Issuance Pipeline
1. Parse and validate request payload.
2. Retrieve client record; verify secret via `subtle::ConstantTimeEq`.
3. Determine scopes: default from client config; validate requested scopes subset of allowed list.
4. Derive token expiry (default 3600s) and generate UUID `jti`.
5. Apply template substitution and sign using `jsonwebtoken` crate with loaded key + `kid` header.
6. Emit audit log capturing client, scope, TTL, and request ID.

## 9. Security & Observability
- Enforce HTTPS in production; allow HTTP only for local dev behind reverse proxy.
- Implement rate limiting middleware (IP-based) for token endpoint to deter brute force attempts.
- Provide structured logs (tracing crate) with request IDs and latency metrics.
- Expose `/healthz` for liveness plus `/readyz` that checks key + config loading.
- Store secrets only in memory; restrict file permissions on config directory.

## 10. Testing Strategy
- Unit tests for config parsing, template substitution, token signing, and error handling.
- Integration tests using `reqwest` to hit live server (spawned via `tokio::test`) covering success + failure paths.
- Fixtures for JWKS and discovery responses to ensure spec-compliant fields.
- Add GitHub Actions workflow later (once network permissions granted) to run `cargo fmt`, `cargo clippy`, `cargo test`.

## 11. Incremental Delivery Roadmap
1. **Foundation**: set up Rust workspace, dependencies (Axum, serde, jsonwebtoken, rand, tracing), and base server skeleton.
2. **Config & Keys**: implement loaders, schema validation, watch for reload (optional), unit tests.
3. **Client Credentials Flow**: token handler, credential validation, template-driven JWT issuance.
4. **Discovery & JWKS**: metadata builder and JWKS serialization referencing active signing keys.
5. **Hardening**: logging, metrics, rate limiting, health endpoints, Dockerfile for deployment.
6. **Future Milestones**: migrate secrets to hashed storage, add Vue.js front end + authorization code flow, implement persistent storage (PostgreSQL or SQLite) for dynamic client management.

## 12. Future Enhancements
- Authorization code flow with PKCE, consent UI via Vue.js SPA, and session management.
- Admin API/UI for managing clients, rotating secrets, and toggling scopes.
- Support for multiple signing keys with automated rotation, plus `kid` selection logic.
- Optional refresh tokens, introspection endpoint, and proof-of-possession tokens.

