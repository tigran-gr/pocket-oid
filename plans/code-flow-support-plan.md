# Pocket-OID Authorization Code Flow Support Plan (Status Update)

## 1) Objective
Add **Authorization Code Flow** support to Pocket-OID while preserving the current lightweight architecture and preparing for future OIDC features (PKCE hardening, consent hardening, and persistent storage).

## 2) Current implementation status (as of March 22, 2026)

### ✅ Implemented
- Config schema additions for code flow clients:
  - `redirect_uris`
  - `response_types`
  - `require_pkce`
- In-memory users loaded from `users.json`.
- In-memory auth/session storage using `RwLock<HashMap<...>>`.
- New endpoints:
  - `GET /authorize`
  - `POST /login`
  - `POST /consent`
- `POST /oauth/token` support for `grant_type=authorization_code` with:
  - client authentication
  - redirect URI binding
  - one-time code invalidation
  - PKCE verification when present/required
- Discovery metadata updated for:
  - `grant_types_supported` includes `authorization_code`
  - `response_types_supported` includes `code`
- Basic Rust-rendered login and consent pages.
- Integration coverage for happy-path end-to-end auth code flow.

### ⚠️ Partially implemented / caveats
- Session cookie is `HttpOnly` and `SameSite=Lax`, but not yet `Secure` (suitable for local dev, needs production hardening).
- PKCE is supported, but no dedicated feature-flag gating yet.
- Consent exists, but no durable audit trail.

### ❌ Not yet implemented
- Leptos-based UI (current pages are server-rendered Rust HTML, not Leptos SSR/hydration).
- `GET /consent` route (consent is currently rendered from `/authorize`, submission via `POST /consent`).
- Login/logout middleware and explicit logout endpoint.
- Rate limiting / brute-force protection.
- Durable persistence layer (SQLite/Postgres + repository traits).
- Expanded negative-path tests called out in the original plan:
  - invalid redirect URI rejection path
  - expired/used code rejection path
  - consent denied path
  - broader auth-code token error-path matrix
- Dedicated unit tests for validators/store PKCE helpers.
- Feature flag rollout (`auth_code_flow`) and staged deployment workflow.

## 3) Architecture snapshot

### Domain model in code now
- `User` (`id`, `username`, `password`) in config/runtime memory.
- `Session` (`session_id`, `user_id`, `username`, `auth_time`, `expires_at`).
- `AuthorizationCodeRecord` (`code`, `client_id`, `user_id`, `redirect_uri`, `scope`, `nonce`, `expires_at`, PKCE fields).

### Storage strategy
- **Now**: in-memory stores with opportunistic expiration cleanup on read/consume.
- **Next**: move users/sessions/codes to persistent DB abstractions.

## 4) Remaining execution plan

### Phase 1 — Correctness and compliance completion
1. Add missing auth-code negative integration tests (invalid redirect, denied consent, code replay/expiry).
2. Add unit tests for PKCE verifier and authorization return parsing helpers.
3. Improve redirect/error handling completeness for authorization endpoint edge cases.

### Phase 2 — Security hardening
1. Enforce `Secure` cookies in TLS deployments.
2. Add login/token rate limits and basic lockout policy.
3. Add auditable events for login, consent, and code/token exchange.
4. Validate nonce/state handling more strictly where applicable.

### Phase 3 — Frontend and productization
1. Replace Rust string-based pages with **Leptos** login/consent UI.
2. Improve accessibility and form error UX.
3. Introduce `auth_code_flow` feature flag and rollout toggles.

### Phase 4 — Persistence
1. Introduce repository traits.
2. Implement SQLite/Postgres backends for users/sessions/codes.
3. Preserve one-time code semantics and TTL behavior with DB constraints/indexes.

## 5) Deliverables checklist (updated)

- [x] Config schema updates for code flow clients.
- [x] `/authorize`, login, consent endpoints.
- [x] `/oauth/token` auth code grant support.
- [x] Authorization code store with TTL + one-time usage.
- [x] Session management.
- [ ] Leptos-based login/consent UI.
- [~] Unit + integration test coverage (happy path complete; several negative paths/unit cases pending).
- [x] Updated discovery metadata (`response_types_supported`, `grant_types_supported`).

## 6) Suggested near-term timeline (small team)
- Week 1: Finish test matrix + security hardening baseline.
- Week 2: Leptos UI migration and accessibility pass.
- Week 3: Feature flag rollout + persistence abstraction spike.
