# Pocket-OID Re-Auth Client Type Plan

## 1) Objective

Add a **re-auth** client authentication mode where Pocket-OID acts as an authentication proxy for a downstream client.

For a re-auth client:
- Pocket-OID still owns the downstream OIDC surface: `client_id`, `redirect_uris`, scopes, authorization codes, token endpoint, and signing keys.
- The actual user authentication happens at a configured trusted upstream provider.
- After upstream authentication succeeds, Pocket-OID treats the upstream subject as the authenticated user and issues its own authorization code and tokens to the downstream client.
- Pocket-OID can include upstream authentication material in its own token response/token claims according to an explicit wrapping policy.

The first target should be an upstream OIDC provider, including another Pocket-OID instance. Facebook/Meta can be supported later through an OAuth2 provider adapter because it is not the same contract as standard OIDC.

### Settled product decisions

- Re-auth clients use `consent: "local"`: after upstream authentication, Pocket-OID presents its own consent screen before issuing a downstream authorization code. Any consent-skipping policy is deferred.
- Pocket-OID maps an upstream subject to its local subject as `{provider_id}:{upstream_sub}`. For example, an upstream subject of `user-123` from `partner-pocket-oid` becomes `partner-pocket-oid:user-123`.
- The initial release must not embed raw upstream token strings or copy an entire upstream token payload into the final Pocket-OID token. Any upstream claim propagation, token reference, or encrypted-token design requires a future explicit consumer requirement and policy.
- The initial release supports only short-lived access and ID tokens. It does not issue, store, or use refresh tokens.
- Trusted providers are globally defined in `trusted_providers.json`; each re-auth client references a provider by ID. Provider settings and secrets are not embedded in individual client records.
- OIDC provider endpoints are obtained through the issuer's `/.well-known/openid-configuration` metadata. Pocket-OID validates that the discovered metadata's issuer exactly matches the configured trusted issuer.

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
      "consent": "local"
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
    "token_endpoint_auth_method": "client_secret_post",
    "require_pkce": true
  }
]
```

Notes:
- If `type = "oidc"`, validate issuer, audience, signature, expiry, nonce, and state.
- Later provider adapters can add `type = "oauth2_userinfo"` for providers like Facebook/Meta where identity comes from token introspection/userinfo APIs rather than an OIDC ID token.
- `auth_mode` defaults to `"local"` so current clients keep working.

### 3.1 Authorization request parameter policy

- `auth_mode` is registered client configuration, not an `/authorize` request parameter.
- Pocket-OID resolves `auth_mode` from the validated `client_id`; a browser request cannot override or weaken it.
- An `auth_mode=local` or `auth_mode=re_auth` query parameter must not influence authentication routing. It should be treated as an unrecognized extension parameter and ignored.
- If clients later need to suggest one of several permitted upstream providers, add a vendor-prefixed hint such as `pocket_oid_idp_hint=keycloak-local`.
- A provider hint is advisory only. Pocket-OID must check it against the providers explicitly allowed for the registered client and reject unsupported values without starting authentication.
- The standard OIDC `prompt=login` parameter remains separate: it requests fresh authentication using the client's configured mode. For a re-auth client, Pocket-OID should propagate an appropriate fresh-login request to the upstream provider; it must not switch the client to local authentication.

## 4) Flow

### 4.1 Downstream authorization request

1. Downstream client calls `GET /authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, and optional PKCE/nonce.
2. Pocket-OID validates:
   - client exists
   - downstream `redirect_uri` is registered
   - response type is allowed
   - requested scopes are allowed
   - PKCE policy is satisfied if required
3. Pocket-OID loads `auth_mode` from the registered client configuration; authorization request parameters cannot override it.
4. If configured `auth_mode = "local"`, keep current local login and consent behavior.
5. If configured `auth_mode = "re_auth"`, create a short-lived pending re-auth transaction and redirect the browser to the upstream authorization endpoint.

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
7. Resolve `upstream_sub` from the validated upstream ID token's `sub` claim, then set the local subject to `{provider_id}:{upstream_sub}`.
8. Optionally fetch upstream userinfo if configured.
9. Continue to Pocket-OID's local consent screen; after consent, issue a local authorization code.

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

The initial implementation must not include upstream token strings or an entire upstream token payload in Pocket-OID tokens. Defer `claims`, `reference`, `raw`, and `encrypted` modes until a concrete consumer requirement defines an explicit, reviewed policy. If `claims` is later enabled, it must use a narrow allowlist rather than copy the whole upstream payload.

Future example rendered claims (only after an approved allowlist policy):

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
  - OIDC providers have an issuer and required client settings
  - discovered OIDC metadata has an exact issuer match and includes authorization, token, and JWKS endpoints
  - raw token embedding requires explicit opt-in

### Runtime state

- Extend `AppState` with `trusted_providers`.
- Extend `AuthStore` with pending re-auth transactions. Do not store upstream token references in the initial release; `reference` mode is deferred.
- Add TTL cleanup on read/consume, mirroring authorization codes.

### Handlers

- Update `/authorize`:
  - resolve `auth_mode` only from the registered client selected by `client_id`
  - ignore any request-supplied `auth_mode` parameter
  - preserve current local flow for `auth_mode = local`
  - branch to re-auth redirect for `auth_mode = re_auth`
  - if provider hints are added later, validate them against the client's provider allowlist
  - interpret `prompt=login` as fresh authentication within the configured mode, not as mode selection
- Add `GET /reauth/callback/:provider_id`.
- Keep local error responses for invalid downstream redirect URI.
- Only redirect to downstream redirect URIs that were already validated and stored in the pending transaction.

### Upstream client module

Add a small OIDC upstream client module:
- discover and validate provider metadata from `/.well-known/openid-configuration`
- build authorization URL from discovered metadata
- exchange code for tokens
- fetch/cache JWKS using the discovered URI
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
- Do not issue, store, or embed refresh tokens in the initial release.
- Consider `acr`, `amr`, and `auth_time` propagation later.

## 8) Test plan

### Unit tests

- Config parsing defaults `auth_mode` to local.
- Re-auth clients fail startup when `provider_id` is missing/unknown.
- Request-supplied `auth_mode` cannot override the registered client mode.
- Provider hints, if supported, accept only providers allowed for the registered client.
- `prompt=login` preserves the registered client mode and requests fresh authentication.
- OIDC discovery rejects metadata with a mismatched issuer or missing required endpoints.
- Upstream authorization URL contains expected state, nonce, redirect URI, scopes, and PKCE challenge.
- Pending re-auth transaction consumes once and expires.
- ID-token validation rejects wrong issuer, audience, nonce, expired token, and bad signature.
- Initial token rendering does not include raw upstream token strings or an entire upstream payload.

### Integration tests

- Re-auth happy path with a local mock upstream OIDC provider.
- Re-auth callback with bad state returns local error and does not issue a code.
- Upstream authentication error maps to downstream authorization error using the stored validated downstream redirect URI.
- Invalid downstream `redirect_uri` never starts upstream re-auth.
- A re-auth client cannot downgrade to local authentication by adding `auth_mode=local` to `/authorize`.
- Token exchange for a re-authenticated Pocket-OID code preserves the provider-prefixed local subject and does not include raw upstream token strings or an entire upstream payload.
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

1. Add OIDC discovery and upstream authorization URL builder.
2. Update `/authorize` to redirect re-auth clients upstream.
3. Add callback route.
4. Exchange upstream code for tokens.
5. Validate upstream ID token.
6. Issue normal local authorization code.

### Phase 4 — Token context propagation (deferred)

1. Extend authorization-code records with the upstream authentication result.
2. Define an explicit consumer requirement and allowlist before extending token rendering with selected upstream claims.
3. Add integration coverage for the approved downstream token contents.

### Phase 5 — Hardening and adapters

1. Add JWKS caching and refresh behavior.
2. Add userinfo support.
3. Add `reference` token wrapping mode if raw upstream token access is required.
4. Add OAuth2/userinfo provider adapter for Facebook/Meta-like providers.
5. Consider encrypted token wrapping if raw upstream bearer tokens must travel inside Pocket-OID tokens.

## 10) Open decisions

No unresolved product decisions remain from the initial list. Future decisions are required before enabling upstream claim propagation, token references, encrypted token wrapping, consent skipping, or refresh-token support.
