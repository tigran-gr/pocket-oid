# Test Case Plan: Authorization Code Flow with Redirect Listener

## Purpose
Validate an end-to-end authorization code flow where a local redirect listener:
1. receives the authorization `code` from the redirect URI,
2. exchanges that `code` at `/oauth/token`,
3. returns a user-facing success page (for example: "Authentication successful, you can close this tab."), and
4. verifies the received `id_token` cryptographically and semantically.

## Scope
- Flow under test: `response_type=code`.
- Client type: confidential client with `client_secret`.
- Redirect mode: loopback/local listener (for CLI/native app style UX).
- Tokens under test: `access_token` and `id_token` (primary focus on `id_token` verification).

## Preconditions
- A test client exists and is configured for authorization code flow with the exact loopback redirect URI used by the listener.
- The provider exposes:
  - authorization endpoint (`/authorize`),
  - token endpoint (`/oauth/token`),
  - discovery endpoint (`/.well-known/openid-configuration`),
  - JWKS endpoint (`/jwks.json`).
- A test user account exists for interactive login.
- The listener can bind to `127.0.0.1:<ephemeral_port>`.

## Recommended Test Data
- `state`: random nonce-like value per run.
- `nonce`: random nonce per run.
- `code_verifier` / `code_challenge` if PKCE is enabled for the client.
- Listener redirect URI example: `http://127.0.0.1:49152/callback`.

## Test Steps
1. **Start local redirect listener**
   - Bind to an available loopback port.
   - Record incoming request path + query.

2. **Build authorization request**
   - Send user to `/authorize` with required parameters:
     - `client_id`, `redirect_uri`, `response_type=code`, `scope=openid ...`, `state`, `nonce`.
     - Include PKCE parameters when required.

3. **Authenticate and grant consent**
   - Complete login and consent UI flow.

4. **Capture redirect on listener**
   - Assert one inbound callback to listener.
   - Assert callback includes `code` and matching `state`.
   - Assert no OAuth error parameter is present.

5. **Exchange code for tokens**
   - POST to `/oauth/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, and client authentication.
   - Include `code_verifier` if PKCE is used.

6. **Validate token response**
   - Assert HTTP `200 OK`.
   - Assert JSON includes `token_type=Bearer`, `access_token`, `id_token`, and expected `expires_in` semantics.

7. **Return success page from listener**
   - Listener responds with `200 OK` and a simple HTML page.
   - Assert response body contains user guidance text, e.g.:
     - "Authentication successful, you can close this browser tab."

8. **Verify `id_token`**
   - Resolve discovery metadata to JWKS URI.
   - Parse JWT header and select key by `kid` from JWKS.
   - Verify signature and token validity checks:
     - issuer (`iss`) matches provider issuer,
     - audience (`aud`) includes `client_id`,
     - expiration (`exp`) is in the future,
     - issued-at (`iat`) within reasonable skew,
     - nonce (`nonce`) equals authorization request nonce,
     - subject (`sub`) is present/non-empty.
   - If `azp` is present, validate per OIDC rules.

## Expected Results
- Authorization redirect reaches the listener exactly once with valid `code` + `state`.
- Token exchange succeeds and returns an `id_token`.
- Listener returns a human-readable completion page indicating authentication completed and the tab may be closed.
- `id_token` verification passes cryptographic signature and claim-level validation.

## Negative Assertions (same test family)
- Reject if `state` mismatches.
- Reject if token endpoint returns non-200 or missing `id_token`.
- Reject if JWT signature fails against JWKS.
- Reject if `iss`, `aud`, `nonce`, or `exp` validation fails.

## Notes for Automation
- Keep listener port dynamic to avoid collisions in CI.
- Add bounded timeouts for callback wait and token exchange.
- Log correlation IDs (`state`, request id) to simplify triage.
