# Pocket-OID Authorization Code Flow Support Plan

## 1) Objective
Add **Authorization Code Flow** support to Pocket-OID while preserving the current lightweight architecture and preparing for future OIDC features (PKCE hardening, consent, and refresh tokens).

## 2) Recommended all-Rust stack
If we want a mostly/all-Rust stack end-to-end, the strongest fit is:

- **Backend**: Axum + Tokio (already aligned with current direction).
- **Frontend**: **Leptos** (recommended) for SSR/hydration options, good ecosystem momentum, and straightforward Rust-first full-stack workflows.
- **Alternative frontend choices**:
  - **Yew**: mature component model, good if you prefer CSR-first architecture.
  - **Dioxus**: ergonomic and multi-target (web/desktop), useful if desktop admin tooling may be needed later.

### Why Leptos is my recommendation
- Rust-first components and routing.
- Flexible rendering model (SSR/CSR) for login/consent pages.
- Works well when minimizing JS/TS footprint is a goal.

## 3) Scope for first code-flow milestone
Implement minimal, standards-aligned code flow for confidential clients:

- `/authorize` endpoint (GET): validates request, authenticates user session, generates short-lived auth code, redirects with `code`.
- `/oauth/token` extension (POST): supports `grant_type=authorization_code` in addition to existing client credentials.
- Basic login UI and consent UI in Rust frontend.
- In-memory storage for authorization codes and user sessions for MVP.
- Optional PKCE support as feature flag in milestone 1; mandatory in milestone 2.

## 4) Architecture changes

### 4.1 Domain model additions
- `User` (id, username, password hash or external auth reference).
- `AuthorizationRequest` (client_id, redirect_uri, scope, state, nonce, code_challenge*, code_challenge_method*).
- `AuthorizationCodeRecord` (code, client_id, user_id, redirect_uri, scope, nonce, expiration, code_challenge*).
- `Session` (session_id, user_id, auth_time, ttl).

### 4.2 Storage strategy
- **MVP**: in-memory stores (`DashMap`/`RwLock<HashMap<...>>`) with expiration cleanup.
- **Next**: move codes/sessions/users to SQLite/Postgres behind repository traits.

### 4.3 Endpoint additions
- `GET /authorize`
- `POST /login` (or integrated auth callback)
- `GET /consent`
- `POST /consent`
- Existing `POST /oauth/token` to add auth code exchange branch.

## 5) Detailed implementation phases

### Phase A — Protocol foundations
1. Extend config schema with:
   - allowed `redirect_uris`
   - allowed `response_types` (`code`)
   - optional PKCE requirement flag per client
2. Add request validation utilities:
   - redirect URI exact matching
   - scope parsing/validation
   - state + nonce handling
3. Define RFC-compliant error helpers for authorization endpoint redirects.

### Phase B — User auth and sessions
1. Add minimal user auth provider:
   - local static users config or trait-based auth adapter
2. Implement signed secure cookies for sessions.
3. Add login/logout handlers and middleware to enforce authenticated session on `/authorize`.

### Phase C — Authorization endpoint and consent
1. `/authorize` validates client and parameters.
2. If no session, redirect to login and resume flow.
3. Show consent screen with requested scopes.
4. On approval, mint one-time authorization code (short TTL, e.g., 60–120s).
5. Redirect to `redirect_uri?code=...&state=...`.

### Phase D — Token exchange
1. Extend `/oauth/token`:
   - validate client auth
   - verify code ownership + redirect URI binding
   - verify PKCE when present/required
   - single-use code invalidation
2. Issue access token using existing template pipeline, plus:
   - `sub` from authenticated user
   - `amr`/`auth_time` optional claims
3. Return standard token response and errors.

### Phase E — Hardening and compliance
1. Enforce strict redirect URI and short code TTL.
2. Add replay protections and auditable events.
3. Add brute-force/rate limits for login and token endpoints.
4. Add issuer/audience/nonce validations where relevant.

### Phase F — Frontend integration (Leptos)
1. Build Rust login + consent pages in Leptos.
2. Keep UX minimal: login form, scope list, approve/deny actions.
3. Integrate server-side validation errors and OIDC error redirects.
4. Add accessibility baseline (labels, keyboard nav, focus management).

## 6) Testing plan

- **Unit tests**:
  - authorize request validation
  - redirect URI checker
  - code creation/expiry/single-use semantics
  - PKCE verifier logic
- **Integration tests**:
  - happy-path auth code flow end-to-end
  - invalid redirect URI rejection
  - expired/used code rejection
  - bad client credential at token exchange
  - consent denied path
- **Security checks**:
  - cookie flags (`HttpOnly`, `Secure`, `SameSite`)
  - state echo correctness
  - no open redirect behavior

## 7) Rollout strategy

1. Ship behind feature flag: `auth_code_flow`.
2. Internal testing with one trusted client app.
3. Enable PKCE-required mode for public clients.
4. Promote from in-memory stores to durable DB.

## 8) Deliverables checklist

- [ ] Config schema updates for code flow clients.
- [ ] `/authorize`, login, consent endpoints.
- [ ] `/oauth/token` auth code grant support.
- [ ] Authorization code store with TTL + one-time usage.
- [ ] Session management.
- [ ] Leptos-based login/consent UI.
- [ ] Unit + integration test coverage.
- [ ] Updated discovery metadata (`response_types_supported`, `grant_types_supported`).

## 9) Suggested timeline (small team)

- Week 1: Phase A + B
- Week 2: Phase C + D
- Week 3: Phase E + F + testing and docs
