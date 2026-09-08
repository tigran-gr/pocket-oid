# Pocket-OID admin console — design proposal

These are high-fidelity visual concepts using sample configuration. They are not a working admin console. All views are read-only.

## Shared structure

Client applications is the landing page. A persistent desktop sidebar contains only Client applications, Users, and Provider settings, with the supplied Pocket-OID logo. Each page has a compact title, a one-sentence description, and an administrator account menu containing Sign out. No Overview, metrics, creation controls, or configuration editors.

White content surfaces, subtle gray dividers, 14–16px body text, 24px page titles, and approximately 52px table rows keep the interface calm and readable. Teal marks links, focus, and selection. Status always includes a word and a distinguishable icon. The existing logo keeps its gradient; the console has no decorative gradients.

## Lists and details

- **Client applications:** search across client IDs and scopes, with case-insensitive matching. Include enabled and disabled clients. Show Client ID, Status, Authentication (Local or Upstream), and Scopes. IDs are native links; row highlighting reinforces the target without replacing link semantics. Preserve query and scroll position on return from details.
- **Client detail:** group Identity, Redirect URLs, Scopes, Authentication, and Tokens. Show complete values and explicit Copy actions. Wrap long URLs and scope lists; do not require hovering or conceal values behind ellipses. Copy actions copy the full unmodified value and announce “Copied” through a polite live region. Copy failure offers text selection.
- **Inheritance:** display the effective algorithm and lifetime beside “Inherited from provider.” Explicit client values instead say “Client override.” Show seconds and their human-readable equivalent. Do not label every default as inherited: only fields that actually inherit provider configuration use that label.
- **Upstream authentication:** show the trusted provider ID as a reference and show upstream scopes separately from the client's scopes. Use the client's re-auth consent policy: “Show local consent” or “Skip local consent.” For local authentication, use its local consent policy. PKCE is shown as Required or Not required. No link to an unimplemented provider-management section.
- **Users:** list username, user ID, and enabled/disabled status. Identify the configured source as JSON or SQLite through fixed metadata, not a selector. A simple detail view contains those same fields and the source. Administrator accounts and upstream identities are excluded. No emails, photos, activity dates, passwords, or hashes.
- **User source semantics:** the illustrated configuration uses SQLite. SQLite has a stored enabled flag; current JSON user entries have no per-user disabled flag and all configured JSON users are enabled. Display “User source: JSON” for that mode, with optional explanatory text “All configured JSON users are enabled.”
- **Provider settings:** read-only definition lists for Identity (name, issuer), Tokens (default algorithm, lifetime), and Login appearance (background value plus a small visual preview). When the background is unset, show “Default background” and preview the existing default treatment; do not invent a configured hex value. No picker or form inputs.

Client secrets are never part of the interface, including masked fields or reveal controls. User credentials are never part of the interface.

## Representative sample configuration

The designs use six registered clients, including two disabled clients. These are illustrative values, not the current deployment's configuration.

| Client ID | Status | Authentication | Scopes |
| --- | --- | --- | --- |
| portal-web | Enabled | Local | openid, default |
| partner-portal | Enabled | Upstream | openid, default, partners:read, partners:write |
| orders-api | Enabled | Local | orders:read, orders:write |
| ops-cli | Enabled | Local | openid, default |
| legacy-web | Disabled | Local | openid |
| sandbox-client | Disabled | Local | default |

Representative detail: `partner-portal`; audience `https://api.example.com/partners`; redirects `https://partners.example.com/auth/callback` and `https://staging.partners.example.com/oidc/authorization/callback`; PKCE required; local consent after upstream authentication; trusted provider `corp-oidc`; upstream scopes `openid`; RS256 and 3,600 seconds inherited from provider.

Provider sample: Pocket-OID; issuer `https://id.example.com`; RS256; 3,600 seconds; configured background `#F2F8F7`.

Users sample: alice / user-alice, bob / user-bob, carol / user-carol, and dave / user-dave. Carol is disabled; the others are enabled. Source: SQLite.

## States

Preserve the navigation shell and page title in every state. Announce search result counts without moving focus. Never show an empty state when a request failed.

| Surface | Loading | Empty or unavailable | No search results | Error |
| --- | --- | --- | --- | --- |
| Clients | Three skeleton rows; “Loading applications…” | “No client applications configured.” Supporting text: “Configured applications will appear here.” | “No matches for ‘billing’.” Clear search. | “Could not load applications.” Retry. |
| Users | Three skeleton rows; “Loading users…” | “No local users available.” Retain the known source label. | “No users match ‘billing’.” Clear search. | “Could not load users.” Retry. Unknown source is “Unavailable,” never guessed. |
| Client/user detail | Skeleton definition rows; descriptive loading announcement | “Client not found” or “User not found”; Back to list. Empty redirects say “No redirect URLs configured”; empty scope lists say “No scopes configured”; unset audience says “Not configured.” | Not applicable | “Could not load client details” or “Could not load user details”; Retry and Back. |
| Provider settings | Skeleton definition rows; “Loading provider settings…” | Required provider settings missing: “Provider configuration unavailable,” not blank values. Optional background uses its actual default. | Not applicable | “Could not load provider settings.” Retry. |

Empty client/user lists are defensive UI states; normal service startup requires enabled clients and users. They do not imply a new valid empty runtime configuration.

## Keyboard and narrow screens

Use semantic navigation, tables and definition lists, a skip-to-content link, named searches, and a visible 2px teal focus ring with a 2px offset. Keep 44px minimum touch targets. Enabled/Disabled icons and text accompany color. Avoid changing focus automatically during search. Loading indicators respect reduced motion.

Below approximately 900px, replace the persistent sidebar with a Menu button and a navigation drawer containing the same three sections. The drawer traps focus, closes with Escape, and restores focus to its opener. Below approximately 640px, list rows become stacked labeled records retaining every column value. Detail views occupy the full width with Back; they are not squeezed into a drawer beside a narrow list. Wrap long identifiers and URLs using `overflow-wrap: anywhere` while preserving their copy value.

Desktop account menus and user-detail drawers have equivalent keyboard dismissal and focus restoration. The desktop inspector alternative becomes a separate detail view on narrow screens. The shell, navigation order, and terminology remain consistent across concepts.
