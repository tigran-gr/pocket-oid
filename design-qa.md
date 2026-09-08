# Leptos admin console QA

Verified 2026-09-08 against the approved option 2 in
`designs/admin-console/prototype`, using its final QA screenshots and
`designs/admin-console/design-notes.md`.

## Scope and implementation

The console uses real Leptos server-rendered components in the existing Axum
service. Its CSS, Inter fonts, Phosphor icons, and Pocket-OID logo are embedded
in the binary. Small external JavaScript enhancements support instant search,
menus, clipboard feedback, and focus/navigation restoration. This is SSR, not
a hydrated WASM application, and requires no separate frontend build.

The three read-only sections use real configuration and local user repositories.
Dedicated administrator authentication is separate from ordinary OIDC login.
There are no browser-based mutation controls or mock records in production.

## Visual comparison

Reference and implementation images were inspected together at matching
1412×894 desktop and 390×844 mobile viewports in the Codex in-app browser.

| Surface | Reference | Implementation | Result |
| --- | --- | --- | --- |
| Clients | `prototype/qa/clients-final.png` | `leptos-qa/clients-desktop.png` | Pass: sidebar, typography, search, columns, status indicators, spacing |
| Client details | `prototype/qa/client-detail-final.png` | `leptos-qa/client-detail-desktop.png` | Pass: all five groups, complete URLs, effective/inherited token settings |
| Users with Alice selected | `prototype/qa/users-final.png` | `leptos-qa/users-matched-desktop.png` | Pass: selected row, inspector proportions, source, copy action |
| Provider with account menu | `prototype/qa/provider-final.png` | `leptos-qa/provider-matched-desktop.png` | Pass with intentional live-preview differences |
| Mobile clients | `prototype/qa/mobile-clients-final.png` | `leptos-qa/clients-mobile.png` | Pass: stacked records, full scopes, navigation, focus styling; no horizontal overflow |

Image paths above are relative to `designs/admin-console/`. Additional evidence
is saved in `designs/admin-console/leptos-qa/`: mobile navigation, mobile client
detail, mobile and desktop disabled-user detail, search no-results, and sign-out.

Intentional differences from the mock:

- The footer says "Read-only console · Configuration loaded at startup."
- Issuer values come from configuration, so the temporary fixture shows its
  actual loopback address instead of `https://id.example.com`.
- Login appearance renders the actual login template in a sandboxed,
  noninteractive iframe instead of displaying a static screenshot. Its internal
  scale differs slightly from the mock's image, while the preview frame matches.
- Focus rings appear when focus is moved to inspector close/menu controls.
- Native SSR navigation uses the browser's loading behavior. No synthetic loading
  delays, mock failure switches, or asynchronous client/provider fetches are added;
  these records are validated before startup. SQLite read failures have a real
  error state and Retry link.

## Interaction and access checks

- Administrator login, separate session cookie, logout, and history revalidation.
- Ordinary user credentials cannot log into the admin console.
- Invalid login/logout CSRF tokens are rejected; login rotates the session token.
- Disabling an administrator invalidates access on the next protected request.
- Search updates results and counts without moving focus; Clear search restores
  all clients. Query parameters preserve the selected filter through navigation.
- Client details expose full copy values and show successful Copy feedback.
  The browser automation clipboard readback was unavailable; exact clipboard
  contents were not independently verified through the OS clipboard.
- User inspector closes with Escape and restores focus to its source link.
- Mobile native navigation dialog closes with Escape and restores Menu focus.
- Account menu opens with ArrowDown, focuses Sign out, and dismisses with Escape.
- Long URLs and mobile user details remain within the 390px viewport.
- Broken SVG namespace duplication found during browser QA was fixed; every
  embedded icon now loads, with regression coverage for namespace uniqueness.
- No browser console warnings/errors were reported during the final navigation.

## Automated verification

- `cargo fmt -- --check`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `cargo test`: passed, 77 tests (25 library, 3 CLI, 49 integration).
- Seven admin-console integration tests cover authentication boundaries, CSRF,
  logout, disabled admins, HTML escaping, credential exclusion, client overrides,
  JSON users, SQLite updates/failures, absent admin configuration, and icon routes.
- `python3 -m unittest discover -s tests_blackbox -v`: passed; 8 automated tests,
  6 opt-in browser/Keycloak tests skipped by their existing configuration.
- `git diff --check`: passed.

Cargo reports an upstream future-compatibility notice for `proc-macro-error2
2.0.1`; it does not fail the current checks. Expiry/rate-limit timing and browser
clipboard failure fallback were not exercised in the browser. No unresolved
blocking visual or functional issue was found in the tested first-release scope.

Temporary preview data used fixture credentials only, separate from the user's
configuration. Verification servers are stopped after QA per repository guidance.
See README's "Administrator web console" section for setup and runtime limits.
