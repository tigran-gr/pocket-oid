# Pocket-OID Re-Auth Client Type Plan

## 1) Objective

Add a **re-auth** client authentication mode where Pocket-OID acts as an authentication proxy for a downstream client.

For a re-auth client:
- Pocket-OID still owns the downstream OIDC surface: `client_id`, `redirect_uris`, scopes, authorization codes, token endpoint, and signing keys.
- The actual user authentication happens at a configured trusted upstream provider.
- After upstream authentication succeeds, Pocket-OID treats the upstream subject as the authenticated user and issues its own authorization code and tokens to the downstream client.
- Pocket-OID can include upstream authentication material in its own token response/token claims according to an explicit wrapping policy.

The first target should be an upstream OIDC provider, including another Pocket-OID instance. Facebook/Meta can be supported later through an OAuth2 provider adapter because it is not the same contract as standard OIDC.

## 2) Terminology

- **Downstream client**: the app that talks to this Pocket-OID instance.
- **Pocket-OID**: this service, acting as the downstream client's OIDC provider.
- **Upstream provider**: the trusted authentication provider where the user actually logs in.
- **Re-auth**: Pocket-OID redirects the browser to the upstream provider, validates the upstream result, then issues its own code/tokens.

## 3) Configuration model

Keep normal clients backwards-compatible by defaulting to local authentication.

Example `clients.json` shape:

```json
[
  {
    "client_id": "app-a",
    "client_secret": "supersecret",
    "audience": "https://api.example.local",
    "scopes": ["openid", "default"],
    "redirect_uris": ["https://app.example.local/callback"],
    "response_types": ["code"],
    "auth_mode": "re_auth",
    "re_auth": {
      "provider_id": "partner-pocket-oid",
      "upstream_scopes": ["openid", "profile", "email"],
      "subject_source": "id_token.sub",
      "consent": "local",
      "token_wrapping": {
        "mode": "claims",
        "claims": ["iss", "sub", "aud", "exp", "email"]
      }
    }
  }
]
```

Add a separate upstream provider config file, for example `trusted_providers.json`:

```json
[
  {
    "provider_id": "partner-pocket-oid",
    "type": "oidc",
    "issuer": "https://partner-idp.example.local",
    "client_id": "pocket-oid-proxy",
    "client_secret": "upstream-secret",
    "redirect_uri": "https://pocket-oid.local/reauth/callback/partner-pocket-oid",
    "authorization_endpoint": "https://partner-idp.example.local/authorize",
    "token_endpoint": "https://partner-idp.example.local/oauth/token",
    "jwks_uri": "https://partner-idp.example.local/jwks.json",
    "userinfo_endpoint": "https://partner-idp.example.local/userinfo",
    "token_endpoint_auth_method": "client_secret_post",
    "require_pkce": true
  }
]
```

Notes:
- If `type = "oidc"`, validate issuer, audience, signature, expiry, nonce, and state.
- Later provider adapters can add `type = "oauth2_userinfo"` for providers like Facebook/Meta where identity comes from token introspection/userinfo APIs rather than an OIDC ID token.
- `auth_mode` defaults to `"local"` so current clients keep working.

## 4) Flow

### 4.1 Downstream authorization request

1. Downstream client calls `GET /authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, and optional PKCE/nonce.
2. Pocket-OID validates:
   - client exists
   - downstream `redirect_uri` is registered
   - response type is allowed
   - requested scopes are allowed
   - PKCE policy is satisfied if required
3. If `auth_mode = "local"`, keep current local login and consent behavior.
4. If `auth_mode = "re_auth"`, create a short-lived pending re-auth transaction and redirect the browser to the upstream authorization endpoint.

### 4.2 Upstream authorization request

Pocket-OID builds an upstream request:
- `response_type=code`
- upstream `client_id`
- configured upstream `redirect_uri`
- configured upstream scopes
- random upstream `state`
- random upstream `nonce`
- PKCE challenge when upstream provider config requires it

The pending transaction stores:
- downstream original authorize request
- downstream client id
- upstream provider id
- upstream state
- upstream nonce
- PKCE verifier
- creation/expiry time

### 4.3 Upstream callback

Add:

```text
GET /reauth/callback/:provider_id
```

On callback:
1. Validate `provider_id`.
2. Validate upstream `state` and consume the pending transaction exactly once.
3. If callback has upstream `error`, convert it to a local downstream authorization error only after using the already-validated downstream redirect URI from the pending transaction.
4. Exchange upstream `code` for upstream tokens.
5. Validate upstream token response.
6. For OIDC providers, validate upstream ID token:
   - signature against upstream JWKS
   - `iss`
   - `aud`
   - `exp` / `iat`
   - nonce
7. Resolve the local authenticated subject from configured `subject_source`.
8. Optionally fetch upstream userinfo if configured.
9. Continue to local consent or directly issue a local authorization code, depending on `re_auth.consent`.

### 4.4 Local code and token exchange

Extend `AuthorizationCodeRecord` to carry the validated upstream authentication result:

```rust
pub struct AuthorizationCodeRecord {
    // existing fields...
    pub auth_context: AuthContext,
}

pub enum AuthContext {
    Local,
    ReAuth(UpstreamAuthenticationResult),
}

pub struct UpstreamAuthenticationResult {
    pub provider_id: String,
    pub upstream_subject: String,
    pub upstream_issuer: String,
    pub upstream_claims: serde_json::Value,
    pub upstream_tokens: Option<StoredUpstreamTokens>,
}
```

During `POST /oauth/token`, when an authorization code has `AuthContext::ReAuth`, use its `UpstreamAuthenticationResult` to render the normal Pocket-OID token and apply the configured wrapping policy.

## 5) Token wrapping policy

The phrase “embed/wrap upstream token inside our token” needs an explicit policy because Pocket-OID currently signs JWTs but does not encrypt them. A signed JWT can be read by whoever receives it.

Recommended modes:

1. `claims`
   - Embed selected upstream ID-token/userinfo claims under a namespaced claim.
   - Example claim: `reauth.provider`, `reauth.iss`, `reauth.sub`, `reauth.claims.email`.
   - Safest first implementation.

2. `reference`
   - Store upstream tokens server-side and embed only a reference id in the Pocket-OID token.
   - Requires persistence or an in-memory short-lived store.
   - Better for raw upstream access/refresh tokens.

3. `raw`
   - Embed upstream token strings directly under a namespaced claim.
   - Should be disabled by default and require explicit config because it exposes upstream bearer tokens to the downstream client/resource server.

4. Future: `encrypted`
   - Add JWE or another encryption envelope and embed encrypted upstream tokens.
   - This is the closest match to true token “wrapping,” but it requires new crypto support and key-management decisions.

Initial implementation should support `claims`, optionally `reference`, and defer `raw`/`encrypted` unless there is a concrete consumer requirement.

Example rendered claims:

```json
{
  "iss": "https://pocket-oid.local",
  "sub": "partner-pocket-oid:user-123",
  "aud": "https://api.example.local",
  "iat": 1773760000,
  "exp": 1773763600,
  "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "reauth": {
    "provider_id": "partner-pocket-oid",
    "issuer": "https://partner-idp.example.local",
    "subject": "user-123",
    "claims": {
      "email": "user@example.local"
    }
  }
}
```

## 6) Code changes

### Config

- Add `ClientAuthMode`:
  - `Local`
  - `ReAuth`
- Add `ReAuthClientConfig`.
- Add `TrustedProviderConfig`.
- Load `trusted_providers.json` from the config directory.
- Validate:
  - every re-auth client references an existing provider
  - upstream redirect URI is non-empty
  - OIDC providers have issuer, authorization endpoint, token endpoint, JWKS URI
  - raw token embedding requires explicit opt-in

### Runtime state

- Extend `AppState` with `trusted_providers`.
- Extend `AuthStore` with:
  - pending re-auth transactions
  - optional upstream token references for `reference` mode
- Add TTL cleanup on read/consume, mirroring authorization codes.

### Handlers

- Update `/authorize`:
  - preserve current local flow for `auth_mode = local`
  - branch to re-auth redirect for `auth_mode = re_auth`
- Add `GET /reauth/callback/:provider_id`.
- Keep local error responses for invalid downstream redirect URI.
- Only redirect to downstream redirect URIs that were already validated and stored in the pending transaction.

### Upstream client module

Add a small OIDC upstream client module:
- build authorization URL
- exchange code for tokens
- fetch/cache JWKS
- validate ID token
- optionally call userinfo

Prefer a focused internal module first. If HTTP mocking becomes painful, introduce a small trait around upstream HTTP calls for tests.

### Token rendering

- Extend `TokenContext` with an optional upstream authentication result.
- Add token-template placeholders for re-auth:
  - `${reauth.provider_id}`
  - `${reauth.issuer}`
  - `${reauth.subject}`
  - `${reauth.claims.<name>}`
- For structured wrapping, consider adding a fixed `reauth` claim after template rendering rather than making users build it entirely through placeholders.

## 7) Security requirements

- Use strong random `state`, `nonce`, and PKCE verifier values.
- Consume pending re-auth transactions exactly once.
- Short TTL for pending re-auth transactions, for example 5 minutes.
- Validate upstream ID-token signature and claims before trusting authentication.
- Never redirect to a callback URI supplied by the upstream callback request.
- Never redirect to a downstream URI unless it came from a previously validated downstream authorization request.
- Namespace upstream claims under `reauth` to avoid collisions with Pocket-OID claims.
- Do not embed upstream refresh tokens in signed-only JWTs.
- Consider `acr`, `amr`, and `auth_time` propagation later.

## 8) Test plan

### Unit tests

- Config parsing defaults `auth_mode` to local.
- Re-auth clients fail startup when `provider_id` is missing/unknown.
- Upstream authorization URL contains expected state, nonce, redirect URI, scopes, and PKCE challenge.
- Pending re-auth transaction consumes once and expires.
- ID-token validation rejects wrong issuer, audience, nonce, expired token, and bad signature.
- Token wrapping renders only configured claims.

### Integration tests

- Re-auth happy path with a local mock upstream OIDC provider.
- Re-auth callback with bad state returns local error and does not issue a code.
- Upstream authentication error maps to downstream authorization error using the stored validated downstream redirect URI.
- Invalid downstream `redirect_uri` never starts upstream re-auth.
- Token exchange for local Pocket-OID code includes configured re-auth claims.
- Code replay still fails.

### Black-box tests

- Run two Pocket-OID instances:
  - upstream instance authenticates the user
  - downstream instance is configured with re-auth client mode
- Browser-style flow verifies downstream client receives a Pocket-OID token with upstream identity context.

## 9) Implementation phases

### Phase 1 — Model and config

1. Add config structs and schema validation.
2. Load trusted upstream providers.
3. Keep all existing local clients working unchanged.
4. Add config tests.

### Phase 2 — Pending transaction store

1. Add pending re-auth transaction records to `AuthStore`.
2. Add create/consume/expiry behavior.
3. Add unit tests for one-time use and expiry.

### Phase 3 — OIDC upstream happy path

1. Add upstream authorization URL builder.
2. Update `/authorize` to redirect re-auth clients upstream.
3. Add callback route.
4. Exchange upstream code for tokens.
5. Validate upstream ID token.
6. Issue normal local authorization code.

### Phase 4 — Token context wrapping

1. Extend authorization-code records with the upstream authentication result.
2. Extend token rendering with selected upstream claims.
3. Add integration coverage for downstream token contents.

### Phase 5 — Hardening and adapters

1. Add JWKS caching and refresh behavior.
2. Add userinfo support.
3. Add `reference` token wrapping mode if raw upstream token access is required.
4. Add OAuth2/userinfo provider adapter for Facebook/Meta-like providers.
5. Consider encrypted token wrapping if raw upstream bearer tokens must travel inside Pocket-OID tokens.

## 10) Open decisions

- Should re-auth clients still show Pocket-OID consent after upstream authentication, or should consent be skipped by default?
- Should local subject be `provider_id:upstream_sub`, a configured claim, or a stable hash?
- Is the downstream client supposed to receive raw upstream bearer tokens, or only upstream identity claims?
- Do we need refresh-token support, or only short-lived access/id tokens?
- Should trusted providers be globally configured in `trusted_providers.json`, embedded per client, or both?
- Should upstream provider metadata be discovered from `/.well-known/openid-configuration` instead of fully configured?
