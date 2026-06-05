# Changelog

All notable changes to connectMWP are recorded here. Each of the three
components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) carries
its own version; entries note which component changed.

## 2.3.4 — 2026-06-04

**Legal pages rewritten + over-broad claims softened (pre-launch).** The privacy policy and terms of service were brought up to the v2 decentralized reality and made more defensible, and a few absolute marketing claims were dialed back to language that can't be read as a guarantee. Marketing-site-only (`connectmwp-server`); plugin and MCP client move in lockstep with no functional change. Verified with a full production build. **Note for the operator:** one blank remains in the Terms — the governing-law jurisdiction — and the legal docs name "Stefan Heinz (2morrow.ai)" as the provider (operating as an individual, not a liability-shielding entity).

### Changed

- **connectmwp-server — privacy policy rewritten** to match the decentralized design and standard data-protection expectations: names the responsible party (Stefan Heinz / 2morrow.ai), carries a "Last updated" date, states plainly that the central site is never in the pairing/auth/publishing path, that the website host records only standard security request logs (IP/browser/time) under legitimate interest, that there are **no analytics cookies or trackers** (verified — the site loads none), distinguishes the device **public key** from SHA-256-hashed API/OAuth tokens, adds a GDPR/CCPA rights section + an explicit "we do not sell your data," and a third-party-links + policy-changes section.
- **connectmwp-server — terms of service rewritten** for defensibility: names the provider, anchors the "as is / no warranty / no liability" language to the **GPLv2 §11–§12** disclaimer the Software is already licensed under, and adds sections for user responsibility for AI content, indemnification, a trademark disclaimer (not affiliated with/endorsed by the WordPress Foundation, Automattic, Anthropic, OpenAI, or Google), governing law (placeholder pending the operator's jurisdiction), and changes/contact.
- **connectmwp-server — softened absolute claims** that could be read as guarantees: the landing hero "Secure, **100%** private" → "Secure, private"; the FAQ "**preventing** token interception or theft" → "**helps prevent** token interception or theft." ("100% free" is unchanged — it is literally true.)

### Unchanged (explicitly preserved)

- The plugin and MCP client are byte-for-byte unchanged apart from the lockstep version bump; the download zip is repacked only to carry the new header (sha `82323ebb…`, both copies identical). No auth, signing, OAuth, token, DAL, or tool behavior changed.

## 2.3.3 — 2026-06-04

**Public site — content brought up to date for all clients, links de-hardcoded.** Pre-launch content pass on connectmwp.com. The site copy and FAQ were written when only the Claude/stdio path existed; this release updates them to cover all three connection methods (device pairing, ChatGPT OAuth, API token), corrects an inaccurate claim about how competing tools authenticate, removes the "active development" warning, and moves every external link into a single config file so none are hardcoded. Marketing-site-only (`connectmwp-server`); the plugin and MCP client move in lockstep with no functional change. Verified with a full production build.

### Changed

- **connectmwp-server — FAQ + landing copy now cover every supported client.** The "what is connectMWP" line, the hero, and the requirements section now name Claude Desktop/Code, Cursor, Cline, **ChatGPT, and Gemini/Antigravity**, and a new FAQ entry ("Which AI clients are supported, and how does each connect?") explains the three connection methods — device pairing (stdio), ChatGPT OAuth, and per-site API token — and points to the plugin's Settings page. The requirements section now makes clear that Node.js is needed **only** for desktop/stdio clients; ChatGPT and token clients connect remotely with no local install.
- **connectmwp-server — corrected the "why we exist" accuracy.** The FAQ no longer says competing tools (incl. Automattic's official adapter) "require active WordPress user sessions" — they authenticate with **Application Passwords / OAuth**, which are login-identity-tied and get blocked at the REST API by 2FA/security plugins. The reworded copy is accurate *and* sharpens connectMWP's real differentiator (session-less, per-request signature auth).
- **connectmwp-server — privacy policy corrected to the v2 (decentralized) architecture.** The policy previously described the central site as a "stateless router during the initial setup handshake" (v1 OAuth-era language). It now states accurately that `connectmwp.com` serves only the info pages + plugin download and is never in the pairing/auth/publishing path; the credential-storage section now distinguishes the device **public key** from the SHA-256-hashed API/OAuth tokens, and notes the private key never leaves the user's machine.

### Removed

- **connectmwp-server — the "⚠️ Active Development — Use at your own risk" banner** was removed from the landing page.

### Internal

- **connectmwp-server — all external links moved to `src/config.json`** (donation, company, repo, support email) — never hardcoded in source or markdown. Components read from config; markdown content uses `{{TOKEN}}` placeholders resolved at render time by a new `applyConfigTokens()` helper. (Closes task T088 and its second instance.)

### Unchanged (explicitly preserved)

- The plugin and MCP client are byte-for-byte unchanged apart from the lockstep version bump; the download zip is repacked only to carry the new header (sha `57e98ed3…`, both copies identical). No auth, signing, OAuth, token, DAL, or tool behavior changed.

## 2.3.2 — 2026-06-04

**Public site — real branding for launch.** Pre-launch polish on connectmwp.com: the marketing site now carries the connectMWP brand mark instead of the default Next.js scaffold, and shared links render a proper social-share card. No plugin, MCP, auth, signing, OAuth, token, or content behavior changed — this release only touches the central marketing site (`connectmwp-server`); the plugin and MCP client versions move in lockstep with no functional change.

### Changed

- **connectmwp-server — the favicon is now the connectMWP chain-link mark**, not the stock Next.js icon. Shipped three ways via the Next.js app-icon file convention so it renders everywhere: a multi-size `favicon.ico` (16–256px, legacy browsers + bookmarks), a vector `icon.svg` (sharp on modern browsers), and a 180px `apple-icon.png` (iOS home screen).

### Added

- **connectmwp-server — social-share (OpenGraph + Twitter) card.** A shared `connectmwp.com` link now previews a branded 1200×630 card (chain-link mark, tagline) on X/LinkedIn/Slack/etc. instead of a blank box. Wired via `metadata.openGraph` / `metadata.twitter` (`summary_large_image`) + `metadataBase` in the root layout, served from `/og-image.png`.

### Removed

- **connectmwp-server — deleted the five unused `create-next-app` scaffold graphics** (`next.svg`, `vercel.svg`, `file.svg`, `globe.svg`, `window.svg`) ahead of the repo going public — they were unreferenced clutter.

### Unchanged (explicitly preserved)

- The plugin and MCP client are byte-for-byte unchanged apart from the lockstep `Version:` header / `package.json` bump; the download zip is repacked only to carry the new header (sha `a3e53b41…`, both copies identical). No auth, signing, OAuth, token, DAL, or tool behavior changed.

## 2.3.1 — 2026-06-03

**Settings page — connections consolidated into one table.** Follow-up to the 2.3.0 redesign. In 2.3.0 each client tab carried its own connection list; this release replaces those three per-tab lists with a **single "Your connections" table below the setup tabs**, so every connection is visible in one place. The tabs are now setup-only. Render-layer change only — no auth, signing, OAuth, token, or DAL behavior changed.

### Changed

- **connectmwp-agent — all connections now live in ONE merged "Your connections" table** below the setup tabs. A **Type** column tags each row — Device key / API token / ChatGPT OAuth — so "what can publish to my site right now?" is answerable at a glance instead of being split across three separate tables. Each row keeps its correct revoke mechanism (device keys via form-post reload; API tokens and OAuth apps via their existing AJAX revoke).
- **connectmwp-agent — the per-tab connection tables were removed.** The setup tabs (Device pairing / ChatGPT / API token) now show only how to connect that client; their connection lists moved to the merged table.

### Internal

- The three connection sources feed the merged table via two new private helpers (`get_cgpt_token_rows()`, `get_oauth_connection_rows()`); the standalone "Connected apps (OAuth)" card render method was removed (its rows + revoke handler moved onto the merged table); the API-token card's generate / one-time-reveal / revoke JS now targets the merged table and is deferred to `DOMContentLoaded` (the table renders lower in the DOM than the card).

### Unchanged (explicitly preserved)

- All three auth paths, every nonce/capability gate, the live pairing-completion poll, the one-time token reveal, the path-token opt-in + its log-exposure warning, and all AJAX generate/revoke actions are unchanged — only the connection **display** was consolidated.

## 2.3.0 — 2026-06-03

**Settings-page redesign — client-first setup.** After OAuth landed in 2.2.0 the plugin's **Settings → connectMWP** page had grown into six stacked cards with no signpost for *which* connection method a given AI client needs — users had to find their own way around. This release reorganizes the page around one question: **"which AI client are you connecting?"** No auth, signing, OAuth, token, or DAL behavior changed — this is a render-layer reorganization only.

### Changed

- **connectmwp-agent — the settings page is now a client-first switchboard.** Three top-level tabs named by the *client family*, each with a one-word method hint, route the admin to exactly the path they need and hide the rest:
  - **Claude · Cursor · Cline** → *Device pairing* (the pairing flow, paired-client list, and the stdio MCP-server snippet).
  - **ChatGPT** → *OAuth sign-in* (the connect steps, connector URL, and the Connected apps list).
  - **Antigravity · Gemini CLI · other** → *API token* (generate-token form, one-time reveal, connector URL, and existing-token list — including the URL-embedded-token log-exposure warning).
  Each tab keeps that client's own connections in context. While a pairing code is live, the device tab leads so the time-sensitive command stays in front.
- **connectmwp-agent — the "Configure an AI client" card was simplified.** The Claude/Cursor/Other sub-tabs collapsed into a single MCP-server snippet plus a one-line "where to put it" note (the snippet was identical across all three). The hero was slimmed to a single descriptive line.

### Unchanged (explicitly preserved)

- All three auth paths (Ed25519 signatures, `cmwp_cgpt_` API tokens, `cmwp_oat_` OAuth), every nonce/capability gate, the live pairing-completion poll, the one-time token reveal, the path-token opt-in + its log-exposure warning, and all AJAX generate/revoke handlers are byte-for-byte unchanged — only their on-page placement moved.

## 2.2.0 — 2026-06-02

**Stable release.** ChatGPT — and any spec-compliant remote MCP client — can now connect to a self-hosted WordPress site and publish, authenticated by full **OAuth 2.1**, with **no central server in the path**. The plugin is its own Authorization Server *and* Resource Server, so the decentralization thesis holds: the client talks straight to the user's site, exactly as Claude/Cursor already do over the signature path. This release graduates the in-development 2.1.1–2.1.4 OAuth work (Phases 0–3) into a single hardened, shippable build.

### Added

- **connectmwp-agent — plugin-hosted OAuth 2.1 (Authorization Server + Resource Server, no central server).** The complete browser-based authorization flow now lives entirely in the plugin:
  - **Discovery** — `.well-known` documents at the site root: RFC 9728 Protected Resource Metadata and RFC 8414 Authorization Server Metadata, so OAuth clients can self-discover the authorization and token surfaces.
  - **Consent** — a **cookie-native, admin-only consent page** at `/connectmwp-oauth/authorize` (a front-end page, not a REST route, so standard WordPress cookie auth recognizes the logged-in admin — no nonce a third-party redirect can't supply). The admin selects which WP user the issued credential acts as.
  - **Token** — `POST /oauth/token` performs **authorization-code + PKCE (S256) exchange** and **refresh-token grant with rotation**. Access/refresh tokens are opaque, stored sha256-hashed (never plaintext), with ~1h access / 30d refresh lifetimes, bound to audience + scope.
  - **Resource access** — `/mcp` now accepts OAuth `cmwp_oat_` access tokens (audience / scope / expiry enforced) alongside the existing `cmwp_cgpt_` API tokens, both routed through the same capability engine.
  - **Client identification via CIMD** (Client ID Metadata Documents): client metadata is fetched over an SSRF-guarded path; authorization codes are single-use and hashed; every redirect carries `iss`; open-redirect is prevented by exact `redirect_uri` matching.
  (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — "Connected apps (OAuth)" admin panel.** View and revoke OAuth connections, grouped and revocable by token family. (`connectmwp-agent/connectmwp-agent.php`)
- **Docs + plugin UI — the 3-way client connection model is now documented.** Three ways a client connects: Claude / Cursor / Cline (stdio + Ed25519 signatures), Antigravity / Gemini CLI / other header clients (per-site API token), and ChatGPT (OAuth 2.1). Settings UI and docs updated to match.

### Hardened (per adversarial review)

- **Admin gate runs BEFORE the outbound CIMD fetch** — an unauthenticated caller can never trigger the SSRF-guarded fetch.
- **Unified HTTPS detection across all auth gates** — one consistent scheme determination for the signature, header-token, and OAuth paths.
- **Peek-before-rotate on refresh** — scope-widening is rejected before the refresh token is consumed, so a rejected refresh no longer destroys the session.
- **Token-request `resource` cross-checked against the grant's bound resource** (RFC 8707) — a mismatched audience is rejected.
- **Per-IP rate limit on the token endpoint.**
- **CSP `form-action` includes the validated client redirect origin** — fixes the post-approval redirect that the consent page's `form-action 'self'` previously blocked.
- **Distinct OAuth resource-server error codes** (`connectmwp_oauth_*`) for precise client and diagnostic feedback.
- **`client_id` length cap** and **`WWW-Authenticate` discovery challenge scoped to `/mcp`.**

### Changed

- **Removed the temporary Phase-0 OAuth spike scaffolding** (observational stub endpoints and the redacted request-log viewer) now that the real OAuth build has landed.

### Unchanged

- **The Ed25519 request-signature path (Claude/Cursor) and the per-site header-token path are unchanged.** OAuth is additive; it does not gate, replace, or alter any existing authentication.

### Bumped

- All three components → 2.2.0 (lockstep). Plugin re-packaged (both zip locations, sha-identical).

---

## 2.1.4 — 2026-06-02 (in-development build, NOT a stable release)

This is an **in-development (pre-release) build**, not a stable release.

### Fixed

- **connectmwp-agent — OAuth consent "Approve" did nothing.** The consent page's Content-Security-Policy `form-action 'self'` also governs the redirect that follows the form POST, so the browser silently blocked the post-approval 302 to the client (e.g. ChatGPT). The CSP now also allows the validated (CIMD-exact-matched) client redirect_uri origin, so approval completes the OAuth redirect. No other behavior changed. (`connectmwp-agent/connectmwp-agent.php`)

## 2026-06-02 — v2.1.3 (in-development build, NOT a stable release)

This is an **in-development (pre-release) build**, not a stable release. It fixes the OAuth consent login loop and lands the OAuth **token endpoint (Phase 2)** — with this, the end-to-end ChatGPT OAuth flow is functionally complete (consent → code → token → authenticated `/mcp` calls). The Ed25519 signature path and the per-site header-token (`cgpt`) path are untouched.

### Fixed

- **connectmwp-agent — OAuth login loop.** The `/oauth/authorize` consent screen is now served as a **cookie-native front-end page** (`/connectmwp-oauth/authorize`) instead of a REST route. REST cookie auth requires a nonce that a third-party OAuth redirect can't supply, so WordPress treated a logged-in admin as logged-out and bounced them back to the login form forever. Standard cookie auth now recognizes the admin. The Authorization-Server-metadata `authorization_endpoint` was repointed accordingly. (`connectmwp-agent/connectmwp-agent.php`)

### Added

- **connectmwp-agent — real token endpoint `POST /oauth/token` (OAuth Phase 2).**
  - **authorization-code + PKCE(S256) exchange** and **refresh-token grant with rotation**.
  - **New access/refresh token DAL** — tokens are opaque, stored sha256-hashed (never plaintext), with ~1h access / 30d refresh lifetimes, bound to audience + scope.
  - **`/mcp` now accepts OAuth `cmwp_oat_` access tokens** (audience / expiry / scope enforced) in addition to the existing `cmwp_cgpt_` API tokens — both via `Authorization: Bearer`, routed through the same capability engine.
  (`connectmwp-agent/connectmwp-agent.php`)

### Hardened (per adversarial review)

- **Token-request `resource` is cross-checked against the grant's bound resource** (RFC 8707) — a mismatched audience is rejected.
- **Refresh scope-widening is rejected BEFORE the token is consumed** (peek-then-rotate) — a rejected refresh no longer destroys the session.
- **Per-IP rate limit on `/oauth/token`.**
- **Distinct `connectmwp_oauth_*` resource-server error codes** for precise client/diagnostic feedback.
  (`connectmwp-agent/connectmwp-agent.php`)

### Not yet implemented

- **Phase 3:** admin grant-management UI, docs/UI client matrix, and removal of the Phase-0 spike stubs.

### Unchanged

- The Ed25519 request-signature path and the per-site header-token (`cgpt`) auth path are unchanged.

## 2026-06-02 — v2.1.2 (in-development build, NOT a stable release)

This is an **in-development (pre-release) build**, not a stable release. It promotes the OAuth spike (Phase 0, observational) into a real, security-hardened **Phase 1 authorization endpoint**, versioned so the build is referenceable and gets its own CHANGELOG line. The flow stops at authorization-code issuance — the token endpoint (Phase 2) is not built yet, so no client can complete an OAuth exchange. The existing Ed25519 signature path and per-site header-token path are untouched.

### Added

- **connectmwp-agent — real `/oauth/authorize` endpoint (OAuth Phase 1).** Replaces the observational stub with a working authorization-code issuer. Key properties:
  - **CIMD client validation behind an SSRF guard.** Client metadata is fetched over **https only**; private, loopback, link-local, and IPv4-mapped addresses are blocked, and redirects are not followed.
  - **Admin-only consent.** The consent screen is login-gated to `manage_options`, with a bound-user selector so the admin chooses which WP user the future credential will act as.
  - **PKCE S256 required** — no `plain`, no missing challenge.
  - **RFC 8707 `resource`/audience binding** to this site's `/mcp` URI.
  - **Single-use, short-TTL (~120s) authorization codes**, stored hashed (never in plaintext).
  - **`iss` on every redirect** and **exact `redirect_uri` matching** (open-redirect protection).
  (`connectmwp-agent/connectmwp-agent.php`)

### Hardened (per adversarial review)

- **Admin gate runs BEFORE the outbound CIMD fetch** — an unauthenticated caller can no longer trigger the SSRF-guarded fetch at all.
- **`X-Forwarded-Proto` is only trusted behind a declared trusted proxy** — otherwise the request's own scheme is authoritative.
- **Pending-code cap enforced** to bound stored authorization-code state.
- **`http://` `redirect_uri`s rejected** (https-only redirect targets).
- **`state` length cap** and **`code_challenge` format validation**.
- **Security headers on the OAuth pages** — `Referrer-Policy`, a Content-Security-Policy, and `X-Content-Type-Options`.
  (`connectmwp-agent/connectmwp-agent.php`)

### Changed

- **connectmwp-agent — OAuth spike-log admin panel readability fix.** The redacted request log no longer renders one character per line, and a **"Copy log"** button was added. (`connectmwp-agent/connectmwp-agent.php`)

### Not yet implemented

- **The token endpoint (Phase 2).** `/oauth/token` is still a stub, so the OAuth flow stops at authorization-code issuance and no client can complete a token exchange yet.

### Unchanged

- **Existing auth paths are untouched.** The Ed25519 signature path (Claude/Cursor) and the per-site header-token path (ChatGPT) work exactly as before. OAuth Phase 1 is additive; it does not gate, replace, or alter any existing authentication.

### Bumped

- All three components → 2.1.2 (lockstep). Plugin re-packaged (both zip locations, sha-identical).

---

## 2026-06-02 — v2.1.1 (in-development build, NOT a stable release)

This is an **in-development (pre-release) build**, not a stable release — it captures the "OAuth Phase 0 spike" work that was sitting on `main` mislabeled as the prior stable `2.1.0`. It is versioned only so the build is referenceable and gets its own CHANGELOG line. (Intended label was the pre-release `2.2.0-dev.1`, but the version tooling rejects non-`X.Y.Z` strings, so it landed as plain `2.1.1`; the convention will be revisited.)

The spike is **observational only** — it adds OAuth *discovery* surfaces and stub endpoints so we can watch how OAuth clients (e.g. ChatGPT) probe and try to connect. There is **no real OAuth yet**; everything here is a learning instrument to be removed when the real build lands.

### Added

- **connectmwp-agent — OAuth discovery documents at the site root `.well-known`.** Serves RFC 9728 Protected Resource Metadata and RFC 8414 Authorization Server Metadata so OAuth clients can discover the (stub) authorization surface. Observational only. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — `WWW-Authenticate` discovery challenge on the `/mcp` 401.** Unauthenticated `/mcp` calls now emit the discovery challenge header that points OAuth-capable clients at the metadata docs above, so we can observe whether/how they follow it. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — stub `/oauth/{authorize,token,register}` endpoints with redacted request logging + an admin viewer.** The endpoints do no real OAuth; they record redacted inbound requests so an admin can inspect what clients send during a connection attempt. Stubs to be removed when the real OAuth build lands. (`connectmwp-agent/connectmwp-agent.php`)

### Unchanged

- **Existing auth paths are untouched.** The Ed25519 signature path (Claude/Cursor) and the per-site header-token path (ChatGPT, shipped in v2.1.0) work exactly as before. The OAuth spike is additive and observational; it does not gate, replace, or alter any existing authentication.

---

## 2026-06-02 — v2.1.0

ChatGPT can now connect to a WordPress site and publish content — without a central server in the path. A new remote MCP endpoint is hosted *by the plugin itself* on the user's site, so the decentralization thesis is preserved: ChatGPT talks straight to the site, exactly as Claude/Cursor already do over the signature path. Connection is by a per-site API token the admin generates on a new settings card and pastes into ChatGPT's connector setup.

### Added

- **connectmwp-agent — new remote MCP transport.** `POST /wp-json/connectmwp/v1/mcp` (plus a path-token variant `/mcp/<token>` for hosts that strip the `Authorization` header) speaks MCP JSON-RPC 2.0 with single `application/json` responses (no SSE). Handles `initialize` / `tools/list` / `tools/call` / `ping`. `tools/call` routes through the shared `dispatch_action()`, so it reuses the same handlers and capability checks as the existing REST + AJAX paths. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — second auth method: per-site API token.** A `cmwp_cgpt_<hex>` bearer token (stored only as a sha256 hash, never in plaintext), bound to a chosen WP user and capability-checked via the existing `user_can($bound_user_id, …)` model. HTTPS-enforced, IP rate-limited, revocable, with NO login session established — same session-less thesis as the signature path. Verified by a new `verify_token_request` route `permission_callback`. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — "Connect ChatGPT (beta)" admin card.** Generate, list, and revoke tokens; per-site hard cap of 20 live tokens; copy-paste connector URL + token and paste-into-ChatGPT instructions. (`connectmwp-agent/connectmwp-agent.php`)

### Changed

- **connectmwp-agent — signature-gate exceptions are now two.** The `rest_pre_dispatch` central filter (`central_rest_auth`) now bypasses the Ed25519 signature gate for `/mcp` (and `/mcp/<token>`) in addition to `/enroll` — but auth is NOT removed: it moves down to the route's `verify_token_request` permission_callback, and the no-cache headers still fire first. Authorization was split from authentication into reusable `cap_can_*` helpers plus a defense-in-depth auth guard in `dispatch_action()`. (`connectmwp-agent/connectmwp-agent.php`)

### Known limitation

- **No media upload over the ChatGPT/MCP path.** `connectmwp_upload_media` is multipart-only and ChatGPT can't send multipart over JSON-RPC, so it is omitted from the MCP `tools/list` (a direct call returns a clear error). ChatGPT can still create / update / publish posts, manage tags and categories, and set `featured_media` by id. Media upload remains available via Claude/Cursor over the stdio signature path. A JSON-native upload path is a possible fast-follow.

### Bumped

- All three components → 2.1.0 (lockstep). The signature path for Claude/Cursor/Cline is UNCHANGED. Plugin re-packaged (both zip locations, sha-identical).

## 2026-06-02 — v2.0.37

Added a way to see, at a glance, which connectMWP version is actually running — both the local client and the plugin deployed on a site. This directly addresses the "which version is Claude Code vs Claude Desktop running?" confusion: ask the assistant to "check connectmwp status" and it reports the client version, the paired sites, and (via a live signed round-trip) the plugin version installed on the target site.

### Added

- **connectmwp-mcp — new `connectmwp_status` tool.** Returns the running MCP client version, the paired sites + which is default, and — through a live signed `/whoami` round-trip — the target site's installed plugin version, site title, and bound user. Degrades gracefully: with no sites paired, or if the round-trip fails, it still reports accurate local facts and an explanatory note. If signing works but the site runs a pre-2.0.37 plugin (no version field), it says so explicitly. (`connectmwp-mcp/index.js`)
- **connectmwp-agent — `/whoami` and `/enroll` identity payload now includes `site.plugin_version`.** Read at runtime from the plugin header via the existing cached `version()` helper; additive, so the `/enroll` ⇄ `/whoami` shape parity is preserved. (`connectmwp-agent/connectmwp-agent.php`)

### Bumped

- All three components → 2.0.37 (lockstep). Plugin re-packaged (both zip locations, sha-identical).

## 2026-05-31 — v2.0.36

Completed the rename on the distribution side: the plugin is now shipped as `connectmwp.zip` and installs into a `connectmwp/` folder (matching the WordPress.org slug), replacing the old `connectmwp-agent.zip` / `connectmwp-agent/` install folder. No code, behavior, or auth-path change. The source working directory remains `connectmwp-agent/` (build stages it into a `connectmwp/` folder); the v2.0.35 note that the source filename is unchanged still holds.

> **Operational note:** because the installed plugin folder changes from `connectmwp-agent/` to `connectmwp/`, redeploying to an existing site (2morrow.ai) is effectively a fresh install of the new folder — deactivate/remove the old `connectmwp-agent` copy after activating the new one. Paired keys live in user meta (not the plugin folder), so existing pairings are unaffected.

### Changed

- **Distribution artifact renamed** `connectmwp-agent.zip` → `connectmwp.zip` at both locations (gitignored repo-root build copy + committed `connectmwp-server/public/connectmwp.zip` served at `https://connectmwp.com/connectmwp.zip`); internal top folder is now `connectmwp/`. (`connectmwp-server/public/connectmwp.zip`, `.gitignore`)
- **connectmwp-server — landing-page download link** updated to `/connectmwp.zip`. (`connectmwp-server/src/app/ClientPage.tsx`)
- **Docs** — `OPERATIONS.md`, `README.md`, and `CLAUDE.md` zip-build commands and references updated to the new artifact name + `connectmwp/` staging folder.

## 2026-05-31 — v2.0.35

Plugin renamed from "connectMWP Agent" to "connectMWP" so the WordPress.org slug resolves to the brand-exact `connectmwp` (`wordpress.org/plugins/connectmwp/`). Display/identity only — no behavioral, auth-path, or logic change. Lockstep bump across all three components per project rule (only the plugin and the server's download-link label actually changed).

### Changed

- **connectmwp-agent — plugin renamed to "connectMWP".** `Plugin Name` header `connectMWP Agent` → `connectMWP`; `Text Domain` `connectmwp-agent` → `connectmwp` (header-only — the plugin has no translation calls against the old domain, so nothing functional changed); the admin settings-page `<h1>` was updated to match. The source filename `connectmwp-agent.php` is intentionally left unchanged (not required for the slug). (`connectmwp-agent/connectmwp-agent.php`, `connectmwp-agent/readme.txt`)
- **connectmwp-server — download-link label** changed from "WordPress Agent Plugin" to "connectMWP plugin" on the landing page; the `/connectmwp-agent.zip` download path is unchanged. (`connectmwp-server/src/app/ClientPage.tsx`)

## 2026-05-31 — v2.0.34

WordPress.org listing-asset pass on top of the v2.0.33 submission-prep release. No behavioral or auth-path change.

### Changed

- **connectmwp-agent — readme source link filled in.** Replaced the `(your public repository URL)` placeholder in the directory readme with the GPL source-repository URL. (`connectmwp-agent/readme.txt`)

### Added

- **WordPress.org listing artwork — chain-link "connector" mark.** Replaced the initial shield-and-checkmark icon (which read as a *security* plugin) with a chain-link connector icon, after iterating through plug-and-socket and bridge concepts. Rendered the full asset set at exact directory dimensions: `icon.svg`, `icon-128x128.png`, `icon-256x256.png`, `banner-772x250.png`, `banner-1544x500.png`. (in gitignored `_internal/wp-org/assets/`)
- **`_internal/wp-org/SUBMISSION_GUIDE.md`** — end-to-end WordPress.org submission runbook (account → readme/asset validation → SVN trunk/tags/assets layout → submit) with the resolved `connectmwp` slug decision. The privacy disclosure (`_internal/wp-org/PRIVACY.md`) had its contact filled and version anchor refreshed. (in gitignored `_internal/`)

## 2026-05-30 — v2.0.33

WordPress.org submission-prep release. No behavioral or auth-path change — packaging and metadata only. The v2.0.32 security items (T064/T065/T066) were live-WP behaviorally verified on 2morrow.ai before this release (4-way concurrent enrollment race → exactly one winner + three rejected; a Page read through the posts endpoint → 404; duplicate-tag create → generic error, no raw `WP_Error`).

### Added

- **Repo-root `LICENSE`** — canonical GPLv2 text. The repo previously shipped no license file at all. (`LICENSE`)
- **`connectmwp-agent/readme.txt`** — WordPress.org directory readme: header block (Stable tag, Requires/Tested, GPLv2), an **External Services** disclosure documenting that the plugin makes no outbound calls, plus Installation, FAQ, and Changelog sections. (`connectmwp-agent/readme.txt`)

### Changed

- **connectmwp-agent — completed the plugin header for directory review.** Added `Requires at least`, `Requires PHP`, `License URI`, and `Text Domain`; promoted `License` to `GPLv2 or later`; and rewrote the stale `Description`, which still described the v1 "client-level tokens" model rather than the v2 session-less Ed25519 design. No code path changed. (`connectmwp-agent/connectmwp-agent.php`)

## 2026-05-30 — v2.0.32

Backlog-clearing release from two fresh audits (`_internal/SECURITY-REVIEW-REPORT_2026-05-30_10-30.md`, `_internal/ARCH-REVIEW-REPORT_2026-05-30_10-20.md`). Static + build + interop verification green (`_internal/verify/p12_test.sh`, 25/25); live-WP behavioral verification of the security items (T064/T065/T066) pending deploy.

### Security

- **connectmwp-agent — closed an enrollment-code TOCTOU (T064).** Two concurrent requests presenting the same valid single-use pairing code could both mint a key, and because both succeeded a stolen code left no visible "Invalid code" tamper signal for the victim. Consumption is now serialized through an atomic `add_option` claim sentinel (the same primitive as the replay defense), acquired after input validation so a malformed request can't burn a valid code's retry. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — scoped `/posts/{id}` update & delete to the `post` type (T065).** The `edit_post`/`delete_post` meta-cap passes for Pages and other post types an Editor/Admin can edit, so without a type guard the "posts" tool could mutate or trash non-post objects — widening blast radius beyond its contract. Mirrors the guard `get_post` already had. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — stopped echoing raw `WP_Error` text on taxonomy create (T066).** `create_category`/`create_tag` returned `wp_insert_term`'s message verbatim — the one un-normalized upstream-message passthrough in the codebase. Client now gets a fixed string; the raw detail goes to the error log only. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-server — FAQ rendered at build time, not request time (T067).** The landing page read `content/faq.md` via `process.cwd()` per-request; on a read-only serverless filesystem the file may be absent from the bundle, silently degrading the FAQ in production. The page is now `force-static`, baking the FAQ at build like the legal pages. (`connectmwp-server/src/app/page.tsx`)

### Changed

- **connectmwp-agent — promoted signature-timing and client-status magic numbers to named constants (T060, closes part of T034).** `TIMESTAMP_SKEW_SECONDS`, `REPLAY_TTL_SECONDS` (with the documented invariant that it must exceed the skew window), `LAST_USED_THROTTLE_SECONDS`, and the staleness/just-paired thresholds now live in one place. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — single-sourced the 10 MB media cap to a plugin constant (T057).** Removes the duplicated inline `10 * 1024 * 1024` literal + "10MB" string; documents the cross-language contract with the MCP client's `MEDIA_MAX_BYTES`. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — extracted a pure, testable `classify_key_status()` (T055, partial).** The "just-paired / stale" business rules are now an SSOT method instead of inline in the settings render loop. (Asset-enqueue extraction of the inline CSS/JS deferred — needs live-WP verification.) (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-server — extracted shared `PageShell` / `GlassCard` surfaces (T059, closes part of T034).** The page shell + frosted card, previously hand-copied across the landing and legal pages, are now one component. (`connectmwp-server/src/components/Surfaces.tsx`)

### Performance

- **connectmwp-agent — retired the O(N) key fan-out on the 3-second pairing poll (T058).** `pairing_status_handler` now reads a denormalized latest-client hint + the index length instead of resolving and sorting every key row each poll, falling back to the authoritative scan only when the hint is absent. (`connectmwp-agent/connectmwp-agent.php`)

### Fixed

- **connectmwp-mcp + connectmwp-agent — clipboard "Copied!" no longer shown when the copy fails (T056).** The copy buttons (landing-page pairing command, plugin pairing command + key-id chips) assumed `navigator.clipboard.writeText` always resolved; on a rejection the user was told it copied while the clipboard stayed empty. Now gated on success with a "Press ⌘C" / "select & ⌘C" fallback. (`connectmwp-server/src/app/ClientPage.tsx`, `connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-agent — the pairing-status poll surfaces failure instead of swallowing it (T062).** After repeated failed polls the loop now stops and shows an "auto-refresh paused — reload" notice rather than failing silently. (`connectmwp-agent/connectmwp-agent.php`)
- **connectmwp-mcp — `bin` path normalized to `index.js` (T054).** Drops the leading `./` that triggered an `npm warn publish "bin[...] script name was cleaned"` on every publish. (`connectmwp-mcp/package.json`)

### Accessibility

- **connectmwp-agent — Configure-card tabs are now real `<button role="tab">` elements (T061).** The Claude/Cursor/Other switcher was mouse-only clickable `<div>`s; it now has keyboard operation, arrow-key navigation, and `role="tablist"`/`aria-selected`. (`connectmwp-agent/connectmwp-agent.php`)

### Bumped

- All three components → 2.0.32 (lockstep). Plugin re-packaged (both zip locations sha-identical).

## 2026-05-29 — v2.0.31

### Fixed — P11 (plugin)

- **The pairing screen no longer leaves behind a tab-focus watcher after it finishes (T042).** While you have a live pairing code on screen, the WordPress Settings → connectMWP page checks every few seconds whether the pairing completed, and also re-checks the instant you switch back to that browser tab. Previously, once pairing finished (success) or the code expired, that "switch-back" watcher was never removed — a harmless leftover the browser would only clear when you left the page. It is now removed the moment polling stops. As part of the fix, the page's stop logic (mark stopped, clear the timer, remove the watcher) was consolidated into one place, so it can't drift out of sync again. This is admin-screen behavior only — it does not touch the AI-to-WordPress publishing path, signatures, sessions, or any authentication.

### Internal — P11

- All three components bumped to **v2.0.31** in lockstep (project rule), even though only the WordPress plugin changed.
- Plugin zip rebuilt and mirrored to `connectmwp-server/public/connectmwp-agent.zip` (both copies sha-identical) so it carries the v2.0.31 plugin header.

## 2026-05-29 — v2.0.30

### Changed — central-server cleanups (P10, server-only)

- **The website's FAQ and the three legal pages now share one styling system (T051).** The FAQ answers on the home page and the About / Privacy / Terms pages used to be styled by a hand-maintained set of custom CSS rules that duplicated what a standard typography library already does. They now use that standard system (Tailwind Typography), so the three legal pages and the FAQ look consistent with far less styling code to keep in sync. Links in this content still open in a new tab, carry the safe `noopener noreferrer` attributes, and have their URLs sanitized exactly as before.
- **The page background and card shadows are defined once instead of copy-pasted (T047).** The dark radial background and the card drop-shadows were written inline and duplicated across the home and legal pages. They are now defined a single time and reused. The pages look pixel-for-pixel identical; the source is just cleaner.
- **The website's pairing command now exactly matches the plugin and the docs (T053).** The command shown on the website previously included a redundant `@latest`; it now reads the plain `npx -y connectmwp-mcp …` form, the same as the WordPress plugin's pairing screen and the documentation. The package name and the command template now live in one shared file in the server code.

### Fixed — P10

- **A missing or broken FAQ file is now visible instead of silently swallowed (T050).** If the FAQ content file is missing, unreadable, or empty, the home page still loads normally with a graceful fallback message (the page's main download-and-setup purpose never breaks). The difference: the server now writes a single clear, categorized log line saying exactly which kind of failure happened — missing file, permission problem, empty/garbled content, or something else — so the cause is diagnosable at a glance rather than hidden.
- **The "Copied!" button feedback timer is now cleaned up properly (T046).** Clicking the copy-command button rapidly no longer stacks multiple reset timers, and no leftover timer tries to update the page after you navigate away.

### Internal — P10

- **FAQ accordion answers are now always in the page and shown/hidden with CSS (T048).** Previously each answer was added to and removed from the page on every open/close. Keeping them present makes the accessibility wiring correct at all times and avoids re-processing the answer text on every toggle. Collapsed answers are hidden from both the screen and assistive technology.
- Added `@tailwindcss/typography` as a build-time dependency of the central server.
- All three components bumped to **v2.0.30** in lockstep (project rule), even though only the central server changed.
- Plugin zip rebuilt and mirrored to `connectmwp-server/public/connectmwp-agent.zip` (both copies sha-identical) so it carries the v2.0.30 plugin header.

## 2026-05-29 — v2.0.29

### Changed — taxonomy pagination parity + pagination-limit SSOT (P9, plugin)

- **Tags and categories now tell AI clients how many exist (T049).** Listing your tags or categories used to return only the current page with no signal that more existed, so an AI client had to keep guessing offsets and re-asking until it hit an empty page — wasting tokens and round-trips. Both lists now report the full count and a clear "there's more" flag, exactly the way the posts list already did, so a client can fetch precisely the next page and stop when it's done. The count respects the same filters as the listing (it counts every tag/category, empty ones included, and honors any search term), so paging through a filtered list behaves correctly.
- **Pagination limits live in one place now (T052).** The default page size and the maximum page sizes were previously hard-coded separately inside each list endpoint. They are now single named settings at the top of the plugin. Behavior is unchanged on purpose: posts still cap at 100 per page, tags and categories at 200, default 50 — the deliberate difference between posts (whose rows can carry large content) and taxonomies is preserved, just no longer scattered across the code. The taxonomy cap and default deliberately mirror the MCP client's own page-size settings, and a verification check now guards against the two drifting apart.

### Internal — P9

- Plugin (`connectmwp-agent/connectmwp-agent.php`): added class constants `DEFAULT_PER_PAGE` (50), `MAX_PER_PAGE` (200, taxonomy cap), `MAX_PER_PAGE_POSTS` (100, posts cap), `MIN_PER_PAGE` (1) and replaced the inline `50` / `min(100, …)` / `min(200, …)` literals in `get_posts_handler`, `get_tags_handler`, and `get_categories_handler` with `self::` references. `get_tags_handler` and `get_categories_handler` now compute `total` via `wp_count_terms()` (honoring the listing's `hide_empty=false` + `search`) and `has_more` via the exact `($offset + count($result)) < $total` formula `get_posts_handler` uses (SSOT of response shape). A `WP_Error` from the count degrades gracefully to the page count rather than 500. No auth/permission/session changes — `$this->bound_user_id` only.
- MCP client unchanged: `projectListTaxonomy` already folds `total` into a `pagination` object via `buildPagination`, so the new field surfaces automatically.
- Added `_internal/verify/p9_test.sh` (static-always layer asserting the constants, the absence of inline literals, `wp_count_terms`, and the `total`/`has_more` shape in both taxonomy handlers; a Node layer proving the plugin shape produces a `pagination` object and that an offset past the end yields `has_more=false`/`next_offset=null`; and a WP-CLI-gated behavioral layer that skips cleanly without WordPress). All existing harnesses (`interop`, `sanitization`, `p2`–`p5`, `p6_idor`, `p6_enroll`, `p7`, `tool_error_sanitization`, `config_error_classes`) still pass.

### Changed — versioning

- **Bumped all three components to v2.0.29 (lockstep)** via the `/VERSION` SSOT + `scripts/sync-version.mjs`. **Plugin changed — the plugin zip was repackaged and mirrored to `connectmwp-server/public/connectmwp-agent.zip` (byte-identical sha).**

## 2026-05-29 — v2.0.28

### Fixed — MCP client error handling & observability (P8)

- **Tool failures no longer leak internal detail to the AI (security, MEDIUM — T040).** When a publishing tool hits an error, the AI client now receives a single, generic message — `Tool execution failed — see local connectMWP diagnostics (stderr).` — instead of the raw error text. Previously the raw text could expose a filesystem path, your username, or other internal state in the chat transcript. The full technical detail (message, error code, stack) is still written to the local diagnostics stream (stderr) so a developer or support engineer can troubleshoot. Signing-specific errors keep their existing helpful wording, and the "Unknown tool" signal is preserved.

- **Config & version load errors are surfaced instead of silently swallowed (architecture, MEDIUM — T044; absorbs/closes backlog T033).** Previously, a corrupt `~/.connectmwp.json` (a truncated write or a bad hand-edit) made all your paired sites silently vanish — `list-sites` said "No sites configured" with no hint that a recoverable file problem had occurred. Now the three cases are told apart: a genuinely missing file on first run stays silent (expected); a corrupt file prints a clear notice — "your paired sites are NOT lost — fix or restore the file" — plus a diagnostics line; an unreadable file (permissions / I/O) is logged before falling back. The runtime version loader likewise logs before falling back to its built-in version.

### Internal — P8

- New SSOT helpers in `connectmwp-mcp/index.js`: `toClientErrorMessage()` + the exported `GENERIC_TOOL_ERROR` constant (one error→message mapper for the CallTool catch-all), `classifyReadError()` (ENOENT→missing / SyntaxError→corrupt / EACCES→unreadable), and `noticeIfCorrupt()` (single-sourced CLI corrupt-config notice). `readConfig()` split into read-then-parse so first-run ENOENT stays silent while corrupt JSON is always surfaced. New helpers exported past the `isMainModule()` guard for harness import.
- Added `_internal/verify/tool_error_sanitization_test.sh` (T040) and `_internal/verify/config_error_classes_test.sh` (T044).

### Changed — versioning

- **Bumped all three components to v2.0.28 (lockstep)** via the `/VERSION` SSOT + `scripts/sync-version.mjs`. **MCP-client-only change — the WordPress plugin was not touched, so the plugin zip is unchanged (not repackaged).** All existing verification harnesses (`interop`, `sanitization`, `p2`–`p5`, `p6_idor`, `p6_enroll`, `p7`) plus the two new P8 harnesses pass.

## 2026-05-29 — v2.0.27

### Fixed — plugin data-integrity + performance (P7)

- **Data-loss race in paired-key storage (security/integrity, HIGH — T039).** Every paired client's key used to live in one shared database record that the plugin rewrote in full on each change. Under concurrent activity — for example a brand-new pairing arriving at the same instant an existing client made a request — one process could overwrite the other's change, silently dropping a just-paired key (it would show as "paired" on the user's machine but never actually authenticate) or even undoing a revoke. Each key now lives in its **own** database record, so a change to one key can no longer clobber another. Existing pairings are migrated automatically and **non-destructively** on upgrade — nothing the user set up before needs redoing, and the old combined record is kept (read-only) for one release as a safety net.

- **Slow "Paired Clients" settings page with many clients (cleanup, LOW — T043).** The plugin's admin settings screen looked up each paired client's WordPress user one at a time. It now fetches them all in a single query, so the page stays fast regardless of how many clients are paired. The table shows exactly the same information as before (login, display name, roles, the "Unknown User" fallback for a deleted user).

### Internal — P7

- **One key-storage data-access layer (DAL / SSOT).** All key reads and writes now go through a single set of helpers (`get_key` / `save_key` / `add_key` / `update_key_fields` / `delete_key` / `list_keys`, plus `index_add` / `index_remove` / `rebuild_key_index` / `key_option_name` / `normalize_key_record`). No code outside the DAL touches key storage directly — enforced by a grep gate in the verification harness. Per-key rows are the source of truth; a self-healing index lists the ids for cheap enumeration and is fully rebuildable from the rows.
- **Migration is one-time, sentinel-guarded (atomic `add_option`), and idempotent** (`maybe_migrate_legacy_keys`, fired on `plugins_loaded` so it runs on a plugin update; also lazily per-entry on read). It preserves all six stored fields per key (public key, bound user, label, created, last-used, last-IP) and **retains the legacy combined record this release** as a backward-read fallback.
- **Follow-up (v2.0.28):** drop the now-redundant legacy `connectmwp_keys` record after confirming all installs have migrated. Captured here so it is not forgotten.
- Added `_internal/verify/p7_test.sh`: an always-on static layer (DAL present, SSOT grep gate, atomic primitives, non-destructive migration, index recovery, batched settings render, auth-model invariants unchanged) plus a WP-CLI-gated behavioral layer (migration correctness, the concurrency race reproduction, and the T043 query-count proof) that skips cleanly when no WordPress is available.

### Changed — versioning

- **Bumped all three components to v2.0.27 (lockstep)** via the `/VERSION` SSOT + `scripts/sync-version.mjs`. Plugin zip rebuilt and mirrored to `connectmwp-server/public/` (sha-identical). All existing verification harnesses (`interop`, `sanitization`, `p2`–`p5`, `p6_idor`, `p6_enroll`) still pass.

## 2026-05-29 — v2.0.26

### Fixed — plugin security hardening (P6)

- **Private and trashed posts can no longer leak to under-privileged clients (T038, HIGH).** Reading a single post (`GET /connectmwp/v1/posts/<id>`, over both REST and the admin-AJAX fallback) now checks per-object read permission for **every** post status, not just drafts. Previously a key bound to a lower-privilege WordPress role (e.g. a Contributor) could fetch another author's *private* post, or any *trashed* post, and get the full body back — a broken object-level authorization (IDOR) gap. The fix routes every single-post read through one shared check that uses WordPress's own object-level read rule, so the answer matches exactly what that user would be allowed to read in the WordPress admin. Well-behaved Author/Editor/Administrator clients are unaffected; only the previously-leaking case now returns a 403. The list, update, and delete paths were already correct and gained regression coverage.

- **Malformed enrollment requests no longer create database rows (T041, MEDIUM).** The one-time pairing endpoint (`/enroll`) has a per-IP rate limiter. Previously, any request carrying a wrong-but-non-empty code wrote a rate-limit record to the database, so a flood of garbage codes from many source addresses could bloat the WordPress options table. Now a structurally-invalid or missing code is rejected up front with **zero** database writes; only a correctly-shaped (real or brute-forced) code counts against the 5-attempts-per-10-minutes limiter, exactly as before. The client-visible behavior of legitimate pairing is unchanged.

### Added — optional admin setting (P6 / T041)

- **New "Behind trusted proxy" setting (default OFF).** Under **Settings → connectMWP → Network & security**, an administrator can declare that the site sits behind a reverse proxy / CDN they control (Cloudflare, Nginx, a load balancer), so the enrollment limiter attributes requests to the real client IP from the forwarding headers. **Default is OFF**, in which case client IPs come from the direct connection and cannot be spoofed — so upgrading changes nothing unless you opt in. Can also be forced via `define('CONNECTMWP_TRUST_PROXY', true);` in `wp-config.php`. New OPERATIONS.md §8 documents this plus the recommended edge rate-limiting (the primary abuse control). Enabling it while *not* actually behind a controlled proxy re-introduces an IP-spoofing vector — leave it OFF if unsure.

### Changed — versioning

- **Bumped all three components to v2.0.26 (lockstep)** via the `/VERSION` SSOT + `scripts/sync-version.mjs`. Plugin zip rebuilt and mirrored to `connectmwp-server/public/` (sha-identical). New verification harnesses `_internal/verify/p6_idor_test.sh` and `_internal/verify/p6_enroll_test.sh` (+ `p6_enroll_shim.php`, `p6_idor_test.php`) added; the full existing harness suite (`interop`, `sanitization`, `p2`–`p5`) still passes.

## 2026-05-29 — v2.0.24

### Changed — module hygiene (P5 modularization step (iii))

- **connectmwp-mcp — extracted `lib/validators.js` (T144 step (iii)).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §1 (CRITICAL — Monolithic God File). The three input-validation functions — `isPrivateIp` (SSRF private/loopback/link-local IP classifier across IPv4, IPv6, and IPv4-mapped-IPv6 forms — T140), `validateImageUrl` (HTTPS-only + DNS-resolve + private-IP rejection that pins the safe IP for the anti-rebinding fetch — T140), and `validateImageMagicNumbers` (magic-number sniff guarding against arbitrary-file-read — I-2 Fix) — now live in one focused, header-documented module. `index.js` imports them and re-exports `isPrivateIp` / `validateImageUrl` / `validateImageMagicNumbers` for the verification harnesses. The now-dead `import dns from 'dns/promises'` was removed from `index.js` (`validateImageUrl` was its sole consumer). The monolith shrinks by ~125 lines.

  **No behavior change — function bodies moved verbatim; lockstep bump.** `bash _internal/verify/p2_test.sh` (the direct regression guard exercising `isPrivateIp` / `validateImageUrl` via the `index.js` import) and all five other harnesses still pass.

### Fixed — verification infra

- **`_internal/verify/sanitization_test.sh`** — fixed a pre-existing false-failure in the AC5 throw-site leak audit. Under bash `set -euo pipefail`, the middle `grep -E` returned exit 1 on a no-match (the correct/no-leak case), which aborted the whole script before AC5/success printed. Wrapped the matching grep so a no-match no longer poisons the pipeline (`| { grep -E "…" || true; } |`). Assertion logic and thresholds unchanged.

### Changed — documentation

- All "Verified against" anchors → v2.0.24.

### Bumped

- All three components → 2.0.24 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.23

### Changed — module hygiene (P5 modularization step (i) + (ii))

- **connectmwp-mcp — extracted `lib/constants.js` (T147).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §3 (MEDIUM — Hardcoded Fallbacks & Metadata). `MEDIA_MAX_BYTES`, `MEDIA_MAX_MB`, `ALLOWED_EXTENSIONS`, and `FALLBACK_VERSION` (the legacy `1.2.4` runtime fallback string) now live in a single named module with documentation of why each value is what it is. `index.js` imports the constants instead of declaring them inline. Future P5 steps will route additional configurables through the same module.

- **connectmwp-mcp — extracted `lib/crypto.js` with `buildCanonical()` + `signCanonical()` (T144 step (ii)).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §1 (CRITICAL — Monolithic God File). Before: `callWordPress` (REST) and `callWordPressAjax` (AJAX) each built the 6-field canonical inline and ran their own PEM-read + `crypto.sign` + try/catch. Two copies of the byte-identical-with-PHP signing primitive, two copies of the catch block routing through `sanitizeSigningError` + `logDiag`. After: `buildCanonical(parts)` joins the array with `'\n'` at a single named seam (documented as the byte-format invariant that must match the plugin); `signCanonical(canonical, privateKeyPath, ctx, deps)` reads the PEM, signs, returns base64, and funnels the error through dependency-injected helpers (the error helpers stay in index.js for v2.0.23; the next P5 step extracts them to `lib/errors.js`). The byte-format invariant now has ONE place to read.

  **Byte-identical with v2.0.22 — proved by harness.** `bash _internal/verify/interop_test.sh` still passes: Node signs, PHP reconstructs the canonical the same way, `sodium_crypto_sign_verify_detached` succeeds. `bash _internal/verify/p5_test.sh` adds explicit unit tests on `buildCanonical` (exact byte output for 3-part and 6-part inputs) and `signCanonical` (round-trip with a fresh keypair; sanitizer-wrapped error on bad path).

### Added — verification

- **`_internal/verify/p5_test.sh`** — 9-assertion proof of the extracted primitives. Run after any change to `lib/constants.js` or `lib/crypto.js`.
- **`_internal/verify/p2_test.sh` updated** — AC6 now expects 0 cap literals in `index.js` and 1 in `lib/constants.js` (the lift target). All other ACs unchanged.

### Changed — documentation

- All "Verified against" anchors → v2.0.23.

### Bumped

- All three components → 2.0.23 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.22

### Changed — BREAKING (response shape)

- **connectmwp-mcp — tool responses now flow through a projection layer that strips tautological fields and adds explicit pagination metadata (T143 + T148).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §1 (HIGH — "Blind Proxy" Over-fetching) + §4 LOW (missing pagination safety on get_posts). New `connectmwp-mcp/lib/projections.js` module — pure functions, zero I/O, one projection per tool family — wired into every tool handler between `callWordPress` and `JSON.stringify`. Dropped fields by tool:

  - **All success responses (every tool):** the tautological `success: true` field is removed. The MCP envelope's absence-of-isError already signals success; carrying `success: true` on every response was redundant noise that the LLM had to read on every call.
  - **`connectmwp_get_post` / `connectmwp_get_posts` (post entities):** the duplicate `link` field is removed when it equals `url` (the plugin always sets both to the same permalink — carrying both wastes tokens linearly with post count).
  - **`connectmwp_create_post` / `connectmwp_update_post`:** same `link`/`url` dedupe when they match.

  Error responses (`success: false`) pass through unchanged so the `error` field remains the AI's diagnosis signal. Unrecognized shapes pass through unchanged — projection is never lossy (fail-safe).

  **Pagination metadata (T148):** `connectmwp_get_posts`, `connectmwp_list_tags`, `connectmwp_list_categories` now return a structured `pagination` object alongside the items array, replacing the flat `total` + `has_more` fields:
  ```json
  {
    "pagination": { "total": 247, "per_page": 50, "offset": 0, "next_offset": 50, "has_more": true },
    "posts": [...]
  }
  ```
  `next_offset` is `null` on the last page, so the AI can immediately invoke the next call (`connectmwp_get_posts({ offset: 50 })`) without asking the user "what's the next offset?" Offset-based per Q4.3 Option A (matches the WP REST native pagination shape; no premature cursor abstraction).

  Verified token-cost reduction: a representative 50-post `get_posts` response shrinks from 5214 bytes to 3816 bytes — **26.8% smaller** at the JSON layer alone. Larger savings on richer responses where `link`/`url` dedupe scales linearly. Verified by `bash _internal/verify/p4_test.sh` — 22+ assertions covering each tool, error pass-through, pagination shape on first/last pages.

  **Migration impact (Q4.2 Option C — hard cut + documented enumeration):** Any AI prompt or downstream workflow that explicitly reads `response.success`, `response.posts[].link`, `response.total`, or `response.has_more` needs to be updated. The new field paths are `response.posts`, `response.posts[].url`, `response.pagination.total`, `response.pagination.has_more`. Realistic affected count is near zero — the `_links`-style WP-internal fields the original audit flagged were already stripped by the plugin; this projection is the next layer of polish. No known customer-facing prompt relies on the dropped fields.

### Added — module hygiene

- **`connectmwp-mcp/lib/projections.js`** — first step of P5's modular `lib/` layer (`projectGetPosts`, `projectGetPost`, `projectMutatePost`, `projectDeletePost`, `projectUploadMedia`, `projectListTaxonomy`, `projectCreateTaxonomy`, `buildPagination`).
- **`package.json` `files` field** now includes `lib/**` so the lib/ tree ships in the npm tarball. Verified: `npm pack --dry-run` lists 4 files (`README.md`, `index.js`, `lib/projections.js`, `package.json`).

### Changed — documentation

- All "Verified against" anchors → v2.0.22.

### Bumped

- All three components → 2.0.22 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.21

### Security — HIGH

- **connectmwp-mcp — set 0600 on `~/.connectmwp.json` and 0700 on `~/.connectmwp/` (T149 + T150).** Source: SECURITY-REVIEW-REPORT_2026-05-28_18-58.md §3 (HIGH — Fix This Week). Previously the config file (containing `key_id`s, labels, and private-key paths) was created with the default umask perms (typically 0644) and the keystore directory at 0755 — both world-readable on a multi-user system or shared CI runner. Listing the directory leaked every paired host (one `<hostname>.ed25519` file per host). Two changes: `writeConfig` now passes `{ mode: 0o600 }` AND post-writes `fs.chmod(CONFIG_PATH, 0o600)` (covers the overwrite-existing case where mode is ignored). The add-site mkdir uses `{ recursive: true, mode: 0o700 }` AND chmod'd post-mkdir. A new `tightenPathPerms(targetPath, expectedMode)` helper does both the post-create chmod AND silently upgrades existing pre-v2.0.21 installs on the next `readConfig()` — emits one `[connectmwp:diag]` stderr line per tightening event (idempotent on already-tight installs, ENOENT swallowed silently). Windows is a no-op (NTFS doesn't honor POSIX mode bits; ACL-based perms are out of scope per Q3.1 Option A). Verified end-to-end: `bash _internal/verify/p3_test.sh` confirms 0644→0600 + 0755→0700 transitions, second-call idempotency, ENOENT swallowed.

### Added — module hygiene

- **`tightenPathPerms` exported** from `connectmwp-mcp/index.js` for verification harnesses + future test code.

### Changed — documentation

- `_internal/ARCHITECTURE.md` §8 security checklist — add line item for the perms tightening.
- All "Verified against" anchors → v2.0.21.

### Bumped

- All three components → 2.0.21 (lockstep). Plugin re-packaged in both mirrored locations (only the Version header changed; verifies sha-identical between root copy and `connectmwp-server/public/connectmwp-agent.zip`).

## 2026-05-28 — v2.0.20

### Security — CRITICAL

- **connectmwp-mcp — streamed media downloads + uploads with a hard 10MB cap enforced mid-stream (T139).** Source: SECURITY-REVIEW-REPORT_2026-05-28_18-58.md §2 (Incident-Class) + ARCH-REVIEW-REPORT_2026-05-28_19-03.md §2 (HIGH). The previous code path called `imgRes.arrayBuffer()` on the remote fetch response and `fs.readFile(file_path)` on local files, checking size only AFTER the entire payload was in memory — bypassed by chunked-encoded hostile streams with no `Content-Length` header (Node OOM / GC thrash within seconds of a 100MB+ stream). The new path uses a single `streamToCappedBuffer(stream, maxBytes)` helper that drains both Node Readable streams (`fs.createReadStream`) and Web ReadableStreams iteratively, throwing the moment cumulative bytes exceed `MEDIA_MAX_BYTES` and destroying the source so the socket/fd is released immediately rather than waiting for GC. Local files also get an `fs.stat` fast-path that rejects obvious oversized files before reading a single byte. Verified end-to-end: a 100MB chunked-encoded `Content-Length`-omitting hostile server is aborted at ~10MB transferred with RSS growth bounded under ~35MB; a 20MB local file is rejected with zero file reads. `MEDIA_MAX_BYTES` and `ALLOWED_EXTENSIONS` lifted to single top-of-file constants (one place to change; future P5 move to `lib/constants.js`).

- **connectmwp-mcp — pin the validated IP through the HTTP connect step to defeat DNS-rebinding SSRF (T140).** Source: SECURITY-REVIEW-REPORT_2026-05-28_18-58.md §2 (Incident-Class; OWASP API 2023 #7). Previously `validateImageUrl` resolved the hostname, checked the IP against the private-range blocklist, and trusted the URL string going forward — the subsequent `fetch(image_url)` did its OWN DNS resolution. A rebinding attacker controlled a hostname whose first lookup returned a safe public IP and whose second returned `127.0.0.1`, so validation passed and the fetch landed on the user's loopback. The new `pinnedHttpsGet(urlObj, validatedIp, family)` helper uses Node's built-in `https.request` with a `lookup` callback that returns the validation-time IP regardless of what DNS would say at connect time. TLS works naturally because `servername` is set to the URL's hostname (SNI uses the hostname, not the IP). `validateImageUrl` now returns `{ url, validatedIp, family }` instead of side-effecting only. The `isPrivateIp` blocklist was also extended to recognize IPv4-mapped IPv6 forms (`::ffff:127.0.0.1` and similar — a common attacker bypass), the `0.0.0.0/8` block, IPv6 link-local (`fe80::/10`), and IPv6 unique-local (`fc00::/7`). Verified by 22-case unit test of `isPrivateIp` plus a live in-process server that proves the lookup-callback pin lands on the pinned IP, not the system-resolved one.

### Added — module hygiene

- **`isMainModule()` guard around `run()`** so importing `connectmwp-mcp/index.js` from a test harness (or other module) does NOT auto-spawn the MCP stdio server. The bin entrypoint still boots normally — both the direct-node and symlinked-bin invocation paths are handled via `realpathSync`-resolved comparison. Enables clean unit testing of the exported helpers from verification scripts without spawning a stdio server.
- **Exported internal helpers for verification harnesses:** `isPrivateIp`, `streamToCappedBuffer`, `sanitizeSigningError`, `pinnedHttpsGet`, `validateImageUrl`, `MEDIA_MAX_BYTES`, `ALLOWED_EXTENSIONS`. Not part of the public MCP tool surface; subject to P5 modularization.
- **`_internal/verify/p2_test.sh`** — runnable proof of T139 + T140 closure (AC1 streaming abort, AC2 fs.stat fast-path, AC3 IP pinning lands on pinned IP, AC4 22-case IPv6/IPv4-private-range, AC6 constants externalized). Exits non-zero on any regression.

### Changed — documentation

- **`_internal/ARCHITECTURE.md` §8 security checklist** — two more boxes flipped to `[x]` (DNS rebinding closed via IP pinning; media downloads / uploads streamed with hard cap).
- All "Verified against" anchors → v2.0.20 (`CLAUDE.md` project, `OPERATIONS.md`, `SUPPORT_TRAINING.md`, `_internal/ARCHITECTURE.md`).
- `README.md` version line → v2.0.20.

### Bumped

- All three components → 2.0.20 (lockstep). Plugin re-packaged in both mirrored locations (only the Version header changed; verifies sha-identical between root copy and `connectmwp-server/public/connectmwp-agent.zip`).

## 2026-05-28 — v2.0.19

### Security — CRITICAL

- **connectmwp-agent + connectmwp-mcp — close the request-replay window via per-request nonce in the Ed25519 canonical (T137).** Source: `_internal/SECURITY-REVIEW-REPORT_2026-05-28_18-58.md` §1 — broken authentication via missing nonce; OWASP API 2023 #2 + #6. The MCP client now generates a fresh RFC 4122 UUID per request (`crypto.randomUUID()`), sends it in a new `X-ConnectMWP-Nonce` header, and includes it in the canonical signing string at position 2 (between timestamp and method). The plugin extracts the header, validates the UUID shape, and rebuilds the canonical with the nonce in the same position before verifying the Ed25519 signature. The existing sig-hash replay cache (`is_replay_signature` / `cmwp_sig_*` options) is preserved as defense-in-depth — nonce uniqueness makes every signature unique by construction, so the cache continues to catch any literal-replay attempt naturally. **Breaking — hard cut:** v2.0.19 plugin rejects any request without a nonce header with HTTP 401 + error code `connectmwp_missing_nonce`. Pre-v2.0.19 MCP clients fail loudly with a specific code so support can recognize "pinned-old-client" at a glance. No customer-facing docs instruct version pinning (verified at planning time); the recommended `npx -y connectmwp-mcp` auto-pulls the new client. The README's "replay protection is active" claim is now structurally backed by the canonical's nonce field, not just by the after-the-fact sig-hash cache.

- **connectmwp-mcp — sanitize private-key filesystem path out of signing-failure error messages (T138).** Source: same security report §1 — OWASP API 2023 #10 (Unsafe Consumption of APIs). The two former throw sites in `callWordPress` and `callWordPressAjax` interpolated `privateKeyPath` directly into the error message returned to the AI client, leaking the keystore filesystem location into LLM context, chat transcripts, and any client-side logs. New `sanitizeSigningError(err)` helper returns a stable user-facing message per `err.code` (`ENOENT` / `EACCES` / `EPERM` / parse-failure) with the actionable recovery command (`npx -y connectmwp-mcp add-site --enroll …`). A separate `logDiag(msg)` helper writes the full original message (including the path) to stderr with a `[connectmwp:diag]` prefix — captured by the MCP client as an out-of-band log channel, never parsed as JSON-RPC protocol traffic. Stderr safety verified against `@modelcontextprotocol/sdk` StdioServerTransport source (stdout is JSON-RPC exclusive). Full audit of 21 `throw new Error` sites in `index.js` confirms only these two sites were Class A (leaking internal state); all other sites echo only user-supplied values or constant strings. Audit table in `_internal/PLAN_T138_2026-05-28_21-26-39.md` §4.

### Added — diagnostic surface

- **connectmwp-agent — distinguishable WP_Error codes on every verification-failure path** (`connectmwp_missing_nonce`, `connectmwp_invalid_nonce_format`, `connectmwp_missing_credentials`, `connectmwp_timestamp_skew`, `connectmwp_unknown_key`, `connectmwp_malformed_credentials`, `connectmwp_sodium_missing`, `connectmwp_signature_invalid`, `connectmwp_replay_detected`). New private `describe_verification_error($code)` method maps each code to a safe human-readable message (codes are not secrets — the caller can already see the URL, headers, and timestamp). Surfaced through both `central_rest_auth` (REST path → WP_Error) and `handle_ajax_request` (AJAX fallback → wp_send_json_error with `code` + `message` fields). Eliminates the previous generic "Unauthorized" / 401 that masked which check failed.

### Added — interop verification harness

- **`_internal/verify/interop_test.sh`** — runnable Node↔PHP byte-identical canonical proof. Generates a fresh Ed25519 keypair in Node, signs a sample canonical including the nonce, hands the signature + public key to PHP, has PHP reconstruct the canonical the SAME way and verify via `sodium_crypto_sign_verify_detached`. Also asserts AC1 (two different nonces produce different signatures) and Ed25519 determinism (same input → same signature, which is what the sig-hash replay cache relies on).
- **`_internal/verify/sanitization_test.sh`** — runnable T138 sanitization proof. Forces three failure modes (ENOENT, EACCES, PEM-parse) and asserts: user-facing message has no filesystem path; recovery command is present; operator stderr preserves the full path + diagnostic prefix; zero throw sites in `index.js` still reference `privateKeyPath` / `/Users/` / `.ed25519`.

### Changed — documentation

- **`_internal/ARCHITECTURE.md` §4.3 (canonical signing string), §4.4 (verification order), §8 (security hardening checklist).** Canonical template now lists `nonce` as the second field. Verified-against anchor bumped to v2.0.19.
- **`CLAUDE.md` (project) §"Daily runtime path".** Custom-headers list expanded from three to four (`X-ConnectMWP-Key`, `-Timestamp`, `-Nonce`, `-Signature`).
- **`README.md`** — replay-protection sentence updated from generic to concrete (cites the nonce position in the canonical). Version line bumped.
- **`SUPPORT_TRAINING.md`** — new troubleshooting row for the `connectmwp_missing_nonce` 401-with-specific-code symptom (recognize pinned-old-client). Verified-against anchor bumped to v2.0.19.
- **`OPERATIONS.md`** — new section "Replay-blocked verification (T137)" with a copy-paste curl recipe so anyone can confirm the replay window is closed against a paired live site.

### Bumped

- All three components → 2.0.19 (lockstep). Plugin re-packaged in both mirrored locations (root copy gitignored; `connectmwp-server/public/connectmwp-agent.zip` committed; sha-identical to root).

## 2026-05-28 — v2.0.18

### Changed
- **connectmwp-agent — complete redesign of the WP Admin Settings page** following the "calm device-management" point of view (GitHub SSH Keys / Apple Family Sharing aesthetic, not WP-admin-table-busy). Approved design + decision log archived at `_internal/design_pairing_page_v2_2026-05-28/`. Specifically:
  - **State-aware layout** — the page now branches on `$page_state` ∈ {`zero`, `mid-pair`, `paired`}. Zero-state shows a full-card Get Started panel; mid-pair leads with the pairing card; paired leads with the AI clients list.
  - **Status-first information flow** (inverted from old "configure → status" order): the paired-clients list is the centerpiece; the "+ Pair another" button lives in its header; the IDE config sits below as a tinted reference surface.
  - **Per-row status dots** replace the standalone green "Connection Status" banner. Green dot for healthy, grey for stale (no use in 30 days OR never-used + > 7d old). Status is communicated at the row level so it scales to 1, 5, or 50 clients without layout change.
  - **Two-row client cards** in a bordered list with subtle alternating-row backgrounds (`#fff` / `#fbfcfd`) + hairline separators + hover lighten. Row 1: dot + label + optional JUST PAIRED badge + right-aligned Revoke. Row 2 (meta): "paired DATE TIME as USER · last used DATE TIME" + a smaller muted line with the `cmwp_key_…` chip.
  - **Exact timestamps** in `YYYY-MM-DD HH:MM` format, parsed via `wp_timezone()` + `DateTimeImmutable::createFromFormat` (the v2.0.17 fix). Bolded so they read above the muted meta text. Relative phrasings ("X ago") removed from data display — kept only in the transient "What now?" copy. Timezone disclaimer added below the list.
  - **Click-to-copy on key_id chips** with toast confirmation (reuses the existing `showConnectMWPToast` helper).
  - **Tabbed Configure card** (Claude Desktop / Cursor / Other) on a subtle blue-tinted surface (`#f6f9fc`). Replaces the previous side-by-side Cursor + Claude Desktop JSON stack — ~60% less vertical footprint, adds room for ChatGPT Desktop / Cline / Continue without growing the page.
  - **Hero preserved** (deliberate, called "decent" in feedback) with version badge and copy refined to mention more AI clients (ChatGPT Desktop, Antigravity).
  - **Auto-refresh pairing-status polling** from v2.0.16 carried forward unchanged in the mid-pair state's pairing card.
  - **Responsive collapse** at ≤600px: client rows stack to a single column (label / meta / action), pairing-card command-button stacks vertically.

### Bumped
- All three components → 2.0.18 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.17

### Fixed
- **connectmwp-agent — "paired X ago" relative-time label in the Connection Status banner was offset by the WP-vs-server timezone delta.** `current_time('mysql')` stores the key's `created` field in the WP-configured timezone with NO timezone marker on the string. The render code then parsed it with bare `strtotime()`, which silently interprets it as the PHP-server timezone (usually UTC). On a Central-Time WP site sitting on a UTC server, a freshly-paired key displayed "paired 6 hours ago" instead of "just now" — exactly the UTC-CT offset. Reproduced live on 2morrow.ai immediately after the v2.0.16 deploy. Fixed by parsing `created` explicitly with `wp_timezone()` via `DateTimeImmutable::createFromFormat` so the resulting Unix timestamp is correct regardless of how WP and the hosting server's timezones relate. Falls back to the old `strtotime()` path on pre-WP-5.3 installs (where `wp_timezone()` doesn't exist). (`connectmwp-agent/connectmwp-agent.php` — `render_settings_page`)

### Bumped
- All three components → 2.0.17 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.16

### Added
- **connectmwp-agent — live pairing-status polling on the settings page.** When a pairing code is visible, the page now polls a tiny admin-only AJAX endpoint (`action=connectmwp_pairing_status`, nonced, gated by `current_user_can('manage_options')`) every 3 seconds AND immediately on `visibilitychange` (when the tab regains focus — typical when the user returns from their terminal). On detecting a new key (total grew or latest_key_id changed), the pairing card flips to a green "🎉 Pairing successful!" state and reloads after 1.5s so the full new layout (Connection Status banner, "What now?" panel, highlighted Paired Clients row) appears without the user having to manually refresh. Stops polling on success, code expiry, or hidden tab. The success-card DOM is built with `createElement` + `textContent` (no `innerHTML`) so the server-supplied label is structurally XSS-safe regardless of upstream sanitization. (`connectmwp-agent.php` — `pairing_status_handler`, polling JS in `render_settings_page`)

### Bumped
- All three components → 2.0.16 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.15

### Added
- **connectmwp-agent — `Connection Status` banner at the top of the plugin settings page.** Bluetooth-style "you are connected" feedback. Green when 1+ clients are paired, with a count and the most-recent label/time. Neutral gray when no clients are paired. Visible on every page load, not just immediately after pairing. (`connectmwp-agent/connectmwp-agent.php` — `render_settings_page`)
- **connectmwp-agent — `"What now?"` panel** shown for ~1 hour after the most-recent pairing. Confirms identity ("You can now read/write `<site>` as `<display name>` (`<login>`, role: `<roles>`)"), gives a test-it prompt (`"list the tags on this site using connectMWP"`), warns about the AI-client restart-to-reconnect case, and explains how to register the same MCP server in other AI clients (Claude Desktop / Cursor / ChatGPT Desktop / Antigravity) sharing the same pairing.
- **connectmwp-agent — most-recent row highlighted** in the Paired Clients table (green left-border + "✓ new" badge) while the What now? panel is visible. Table is also now sorted newest-first by `created`.
- **connectmwp-agent — `/connectmwp/v1/whoami` REST endpoint** (and `connectmwp_action=whoami` AJAX equivalent). Signature-authenticated, no capability check required. Returns the same identity payload as `/enroll`: `{ site: {title,url}, user: {login,display_name,roles}, capabilities: {edit_posts,publish_posts,…} }`. Used by the MCP client to verify end-to-end signing works post-pairing and by support/diagnostics to confirm what user/capabilities a key resolves to. (`build_identity_payload`, `whoami_handler`, `check_signature_only`)
- **connectmwp-agent — `/enroll` response enriched** with the same identity payload, so the pairing CLI can show a friendly confirmation without an additional round-trip if the round-trip itself fails.
- **connectmwp-mcp — post-pairing /whoami round-trip + enriched CLI summary.** After a successful enrollment, the client now signs a `GET /whoami` request with the brand-new key, prints `✓ Connected to "<Site Title>" (<site_url>) / ✓ Acting as: <Display Name> (<login>) — <roles> / ✓ Can: <friendly capability list> / ✓ Key ID / ✓ Label / ✓ Set as default site` and a test-it prompt. Falls back to the enroll-response payload (with a warning) if the round-trip fails. (`printPairingSummary` helper, `index.js`)
- **connectmwp-mcp — AJAX action mapping** for the new `whoami` endpoint, so the round-trip works on hosts where REST is blocked but admin-ajax isn't.

### Bumped
- All three components → 2.0.15 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-27 — v2.0.14

### Fixed
- **connectmwp-agent — Terminal Pairing Command textarea rendered white-on-white (invisible).** The
  `.cmwp-cmd-textarea` rule was outranked by WordPress admin's `.wrap textarea` selector (same class
  specificity, loaded later globally), so the textarea fell back to WP's default light styling and the
  dark-blue background never applied — making the npx command unreadable even though it was present
  in the DOM (confirmed: selecting the textarea revealed the text). Bumped the selector specificity to
  `.cmwp-wrap textarea.cmwp-cmd-textarea` and added `!important` on `background`/`color` as
  belt-and-suspenders. (`connectmwp-agent/connectmwp-agent.php`)

### Verified (live)
- **v2.0.12 cache-bypass fix confirmed effective on 2morrow.ai.** Authenticated GET emits
  `Cache-Control: no-store, no-cache, must-revalidate, max-age=0, no-store, private` +
  `X-LiteSpeed-Cache-Control: no-cache`; LiteSpeed no longer caches the response
  (`x-litespeed-cache` empty); an immediate unauthenticated request to the same fresh URL returns
  `401 connectmwp_unauthorized` with no leaked data.

### Bumped
- All three components → 2.0.14 (lockstep). Plugin re-packaged.

## 2026-05-27 — v2.0.13

Remediation pass for the day's security & architecture reviews. All three components bumped in
lockstep to 2.0.13 (supersedes the interim working labels 2.0.11/2.0.12).

### Fixed (CRITICAL — found in live testing)
- **connectmwp-agent — unauthenticated draft/content disclosure via edge cache (cache-based auth bypass).**
  On LiteSpeed (common on managed hosts), signed REST **GET** responses were cached and served to
  **unauthenticated** callers hitting the same URL, bypassing the central signature check. Proven live: an
  authenticated `GET /posts` (cache miss, 3 drafts) followed by an unauthenticated request to the same URL
  returned `200` (`x-litespeed-cache: hit`) with those **draft** titles. Root cause: the session-less model
  means WordPress doesn't auto-emit `no-cache`. Fixed by forcing no-store/no-cache on every `connectmwp/v1`
  response (`DONOTCACHEPAGE`, `nocache_headers()`, `Cache-Control: no-store`, `X-LiteSpeed-Cache-Control:
  no-cache`, and the `litespeed_control_set_nocache` action) in `central_rest_auth`.
  **Deploy note:** existing cached entries persist (TTL up to 7 days) — purge the LiteSpeed cache after deploying.

### Fixed
- **connectmwp-mcp — a failed `add-site --enroll` destroyed the existing working key (data-loss).** The enroll
  flow overwrote the site's key before contacting the server and `unlink`ed it on failure, so a failed re-pair
  (e.g. an expired/used 10-minute code) left no usable key. Fixed to stage the new key at a temp path and only
  `rename` it into place after enrollment succeeds; failures remove only the temp key. (`connectmwp-mcp/index.js`)
- **connectmwp-server — legal pages broken by the v2.0.10 CSS migration (regression).** The Tailwind migration
  deleted ~596 lines of `globals.css` but not `legal/[slug]/page.tsx`, which still referenced the removed
  classes — leaving `/legal/privacy|terms|about` unstyled. Rewrote the legal page in Tailwind and replaced a
  stale hardcoded `v1.2.4` badge with the dynamic package version. (`connectmwp-server/src/app/legal/[slug]/page.tsx`)
- **connectmwp-agent — PHP 8.4 implicit-nullable deprecations.** `get_tags_handler`/`get_categories_handler`
  used `WP_REST_Request $request = null` (E_DEPRECATED on 8.4, fatal in PHP 9). Changed to `?WP_REST_Request`.
  Surfaced by `php -l`. (`connectmwp-agent/connectmwp-agent.php`)

### Verified (no change needed)
- The dev's v2.0.10 remediation was reviewed and confirmed correct: central `rest_pre_dispatch` auth is
  namespace-scoped (won't break the site's wider REST API); the replay claim is atomic (`add_option`) with a
  per-request memo preventing double-claim; the multipart body hash is verified against `hash_file()` of the
  actual upload. Live sweep passed term/post pagination, write-replay rejection, and create/delete.
- Backlog (deferred to avoid churn in a security release): magic-number constants, MCP empty-catch logging.

## 2026-05-27 — connectmwp-mcp 2.0.11

### Fixed (data-loss bug)
- **connectmwp-mcp — a failed `add-site --enroll` destroyed the existing working key.** The enroll flow
  wrote the new private key directly over the site's existing key *before* contacting the server, and the
  failure path then `unlink`ed it — so any failed re-pair (e.g. an expired/already-used 10-minute pairing
  code) left the site with **no** usable key (worse than before the attempt). This bit a live session:
  re-running the enroll command with a stale code wiped the working pairing. Fixed to write the new key to
  a temp path and only `rename` it into place **after** enrollment succeeds; the failure path removes only
  the temp key and never touches an existing working key. (`connectmwp-mcp/index.js`)

## 2026-05-27 — connectmwp-agent 2.0.12

### Fixed (CRITICAL — found in live testing)
- **connectmwp-agent — unauthenticated draft/content disclosure via edge cache (cache-based auth bypass).**
  Live testing on 2morrow.ai (LiteSpeed) showed that signed REST **GET** responses were being cached by
  LiteSpeed and then served to **unauthenticated** callers hitting the same URL — bypassing the central
  signature check entirely. Proven: an authenticated `GET /posts` (cache miss) returned 3 drafts; an
  immediate unauthenticated request to the same URL returned `200` (`x-litespeed-cache: hit`) with those
  same **draft** titles. Root cause is a side effect of the session-less model — WordPress only auto-emits
  `no-cache` for *logged-in* REST requests, so session-less signed responses were cacheable. Fixed by
  forcing no-store/no-cache on every `connectmwp/v1` response (`DONOTCACHEPAGE`, `nocache_headers()`,
  explicit `Cache-Control: no-store`, `X-LiteSpeed-Cache-Control: no-cache`, and the authoritative
  `litespeed_control_set_nocache` action) in `central_rest_auth`. (`connectmwp-agent/connectmwp-agent.php`)
  **Deploy note:** existing cached entries persist (TTL up to 7 days) — the LiteSpeed cache must be
  **purged** after deploying this build, then re-verified.

## 2026-05-27 — connectmwp-server 2.0.11, connectmwp-agent 2.0.11

### Fixed
- **connectmwp-server — legal pages broken by the v2.0.10 CSS migration (regression).** The v2.0.10
  commit converted `ClientPage` to Tailwind and deleted ~596 lines of `globals.css`, but did not
  update `legal/[slug]/page.tsx`, which still referenced the now-deleted semantic classes
  (`app-container`, `legal-card-container`, `legal-content`, …) — leaving `/legal/privacy|terms|about`
  unstyled. Rewrote the legal page in Tailwind (consistent with `ClientPage`) and replaced a stale
  hardcoded `connectMWP v1.2.4` badge with the dynamic `package.json` version.
  (`connectmwp-server/src/app/legal/[slug]/page.tsx`)
- **connectmwp-agent — PHP 8.4 implicit-nullable deprecations.** `get_tags_handler` and
  `get_categories_handler` declared `WP_REST_Request $request = null` (implicitly nullable), which
  emits `E_DEPRECATED` on PHP 8.4+ (the target host runs 8.4) and becomes a fatal in PHP 9. Changed to
  explicit `?WP_REST_Request`. Surfaced by `php -l` (the original author had no local PHP).
  (`connectmwp-agent/connectmwp-agent.php`)

### Note
- Completed the dev's v2.0.10 review-remediation pass: verified the central `rest_pre_dispatch` auth
  filter is correctly namespace-scoped (won't break the site's wider REST API), the replay claim is
  atomic (`add_option`) with a per-request memo preventing double-claim, and the multipart body hash
  is verified against `hash_file()` of the actual upload. `connectmwp-mcp` left at 2.0.10 (unchanged).
  Optional cosmetic items (magic-number constants, empty-catch logging) left as backlog to avoid
  churn in a security release.

## 2026-05-27 — v2.0.10

### Fixed
- **connectmwp-agent — secure body hash for multipart uploads.** Enabled body hash header verification (`X-ConnectMWP-Body-Hash`) on `multipart/form-data` uploads (e.g. image uploads) to prevent file intercept/tampering.
- **connectmwp-agent — enrollment rate limiting & SSL enforcement.** Restructured public endpoint `enroll_client_handler` to enforce HTTPS (except localhost) and apply transient-based IP rate limits.
- **connectmwp-agent — correct delete cap.** Gated AJAX fallback deletion on actual `delete_post` user capability instead of generic `edit_post` capability.
- **connectmwp-agent & connectmwp-mcp — paginated list endpoints.** Added support for `limit`, `offset`, and `search` query parameters in tags/categories listing routes to prevent unbounded memory/context issues, and `offset` in post retrieval.
- **connectmwp-mcp — SSRF redirect bypass block.** Disabled automatic redirect following (`redirect: 'manual'`) during image URL downloading, preventing local host port/metadata scans.
- **connectmwp-mcp — arbitrary file disclosure prevention.** Added image buffer magic number validation during uploads to block arbitrary file disclosures via tricky filenames/extensions.
- **connectmwp-server — Tailwind CSS refactor.** Converted custom CSS layout classes inside `ClientPage.tsx` to utility Tailwind CSS layout classes, and cleaned up `globals.css`.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.10`.

## 2026-05-27 — v2.0.9

### Added
- **connectmwp-agent — delete post handler.** Added support for trashing/deleting posts via REST `DELETE` on `/posts/<id>` route.
- **connectmwp-agent — added featured_media, categories, tags to get_post.** Updated `get_post_handler` to return taxonomy lists and the featured media ID by default.
- **connectmwp-mcp — delete post tool.** Registered the new `connectmwp_delete_post` tool and implemented the REST `DELETE` execution pathway (including AJAX fallback routing).
- **connectmwp-mcp — trash status.** Supported the `'trash'` status in the create/update post tool validation enum schemas.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.9`.

## 2026-05-27 — v2.0.8

### Added
- **connectmwp-agent — exposed Last Used column.** Added back the "Last Used" date column in the WordPress admin "Paired Clients" listing table.

### Changed
- **connectmwp-agent — styled Revoke Access button.** Made the "Revoke Access" action button in the "Paired Clients" listing more compact (smaller padding, font-size, and height) to save horizontal layout space.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.8`.

## 2026-05-27 — v2.0.7

### Added
- **README.md — design motivation section.** Added a new "Why connectMWP?" section explaining the advantages of connectMWP (session-less request signatures bypassing security/2FA plugins, direct decentralized calls with $0 middleware proxy costs).
- **connectmwp-server — design motivation FAQ.** Expanded the FAQ page on the website with a dedicated entry answering why connectMWP was built instead of other market solutions.

### Changed
- **README.md — updated pairing delimiters.** Replaced pipe character (`|`) delimiters with shell-safe commas (`,`) in all CLI pairing instructions to prevent terminal command redirect errors.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.7`.

## 2026-05-27 — v2.0.6

### Fixed
- **connectmwp-agent — supported standard link and url fields in post retrieval.** Modified `get_posts_handler` and `get_post_handler` to return the post permalink for both `link` and `url` field requests. This ensures compatibility with AI clients requesting standard REST `link` fields for internal-linking workflow tasks.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.6`.

## 2026-05-27 — v2.0.5

### Fixed
- **connectmwp-agent — layout fix for settings configuration snippets.** Replaced the layout-breaking inline-block block/width styles with standard inline syntax highlight spans (bold blue for the `connectmwp` server block, soft faded grey for surrounding boilerplate). This resolves the alignment issue on closing brackets and eliminates horizontal scrollbar clipping inside the `<pre>` tag.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.5`.

## 2026-05-27 — v2.0.4

### Added
- **connectmwp-agent — dynamic countdown timer.** Added a JavaScript countdown timer in the "Action Required: Go Pair Your Local Environment Now" panel, showing exactly how long (minutes/seconds) remains until the single-use pairing code expires.
- **connectmwp-agent — step-by-step pairing instructions.** Added clear preparation steps in the settings page to guide the user on opening their terminal, checking their local Node.js environment, copying/running the command, and refreshing the settings page to see the client show up in "Paired Clients".

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.4`.

## 2026-05-27 — v2.0.3

### Changed
- **connectmwp-agent — visually highlighted configuration snippets.** Redesigned the Cursor and Claude Desktop JSON config codeblocks inside the settings page to fade out standard `mcpServers` boilerplate and draw focus directly to the `connectmwp` server block.
- **connectmwp-agent — added integration merge tips.** Added a helpful notice above configuration pre-blocks to guide users on merging the server definition block if they have existing MCP servers configured.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.3`.

## 2026-05-27 — v2.0.2

### Changed
- **connectmwp-server — updated onboarding guide copy.** Replaced the obsolete pipe character (`|`) with a shell-safe comma (`,`) in the terminal command copy-block on the homepage to avoid command-line redirections.

### Added
- **connectmwp-server — system requirements and prerequisites FAQ.** Added new sections detailing the requirements (Node.js version, PHP libsodium extension, HTTPS SSL requirement) and instructions on verifying local Node/npm environments.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.2`.

## 2026-05-27 — v2.0.1

### Fixed
- **connectmwp-agent — settings page pairing code display state loss.** Fixed a bug where the generated one-time pairing code was not displayed if the options page was reloaded or redirected. The active unexpired code is now fetched directly from WordPress options on every settings page load until it expires (10 minutes) or is successfully consumed.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.1`.

## 2026-05-27 — v2.0.0

### Added
- **Signature-Based Session-less Authentication:** Rebuilt the entire authentication layer using Ed25519 asymmetric cryptography. The client signs every outgoing request using its private key, and the WordPress plugin verifies request signatures using PHP's native `sodium_crypto_sign_verify_detached` on custom headers (`X-ConnectMWP-Key`, `X-ConnectMWP-Timestamp`, `X-ConnectMWP-Signature`).
- **WAF and 2FA Bypass:** Eliminated WordPress user session creation (`wp_set_current_user` and `determine_current_user` hooks), allowing requests to pass cleanly through 2FA/login-security plugins and WAFs.
- **Local Enrollment Command:** Added `add-site --enroll` command to `connectmwp-mcp` CLI to initiate secure pairing via a short-lived dashboard-generated pairing code.
- **New tools:** Registered `connectmwp_get_post`, `connectmwp_create_category`, and `connectmwp_create_tag` as MCP tools, making the functional API fully aligned with the content creation pipeline.

### Changed
- **Next.js Homepage Redesign:** Replaced the obsolete URL redirect input and OAuth callback flow on `connectmwp.com` with a static step-by-step setup and local pairing instructions portal.

### Fixed
- **Dynamic Plugin Version:** Resolved badge drift by referencing the new class version constant dynamically in the dashboard settings page.

## 2026-05-27 — Architecture (no component version change)

### Changed
- **Decided to re-found auth on session-less Ed25519 request signatures (`_internal/ARCHITECTURE.md` v2).**
  Investigation proved v1's model — logging the caller in as a WordPress user via
  `determine_current_user` — is *generally* incompatible with 2FA/security plugins,
  which discard the login within the same request (401 despite a valid token). The
  v2 design authorizes each *request* by detached signature in the
  `permission_callback`, never creates a WP session, and scopes operations to the
  enrolling user's capabilities via `user_can()`. The local MCP client holds the
  private key (decentralized, no central server in the daily path). Implementation
  pending (handed to the implementing agent). No code shipped in this entry.

## 2026-05-27 — connectmwp-agent 1.2.6

### Fixed
- **connectmwp-agent — every authenticated request self-destructed (401 despite a valid token).**
  `authenticate_request()` runs on `determine_current_user`, which WordPress
  evaluates more than once per request. The single-use replay nonce was claimed
  on the first pass (token recognized, "Last Used" stamped, user authenticated)
  and then **rejected on the second pass** — `add_option()` returns false for an
  already-claimed nonce — causing the filter to return `0` and reset the caller
  to logged-out. By the time the REST/AJAX permission check ran, the user was
  anonymous, so every call returned `rest_forbidden` (401) even for a full
  Administrator with a correct token. Fixed by memoizing the first successful
  token resolution per request (`$resolved_user_id`) and skipping the replay
  re-check on subsequent passes. Affects REST and Admin-AJAX paths alike.
  (`connectmwp-agent/connectmwp-agent.php`)

### Chore
- Synced the admin-page version badge to v1.2.6. Logged a follow-up (T007) to make
  that badge read from the plugin header so it can't drift again.

## 2026-05-27 — connectmwp-agent 1.2.5

### Fixed
- **connectmwp-agent — replace copy alerts with non-blocking inline toasts.** Replaced native browser `alert()` popups with a modern, clean inline toast notification. When copy buttons are clicked, a toast message fades in above the button and auto-fades out after 10 seconds. Re-packaged the WordPress agent plugin.

## 2026-05-27 — connectmwp-agent 1.2.4

### Chore
- **Bump version to 1.2.4.** Updated plugin version headers and dashboard elements to 1.2.4, aligning with the rebranding updates and security remediation fixes made earlier. Re-packaged the WordPress agent plugin.

## 2026-05-27 — connectmwp-mcp 1.2.5, connectmwp-server 1.2.5

### Fixed
- **connectmwp-server — resolve lint warnings & errors.** Cleared unused TS variables and catches in `ClientPage.tsx`. Replaced synchronous state rendering updates in `callback/page.tsx`'s `useEffect` hook with deferred asynchronous state updates to eliminate the React cascade render warnings and block build blocks.

### Chore
- **Completed folder-rename cleanup (`wpConnect` → `connectMWP`).** The project
  directory was renamed on disk; an audit confirmed all in-repo file paths and
  brand references already pointed to `connectMWP`. The one straggler was
  `connectmwp-mcp/package-lock.json`, which still carried the old self-name
  `wpconnect-mcp` (in `name` and `bin`) and a stale self-version `1.0.0`. Synced
  both to match `package.json` (`connectmwp-mcp` / 1.2.5). No functional change.
  (`connectmwp-mcp/package-lock.json`, `connectmwp-mcp/package.json`)

## 2026-05-26 — connectmwp-mcp 1.2.4, connectmwp-server 1.2.4

### Fixed
- **connectmwp-mcp — `get_posts` regression (broken core tool).** The over-fetching
  fix had `get_posts` send a JSON body on a GET request (rejected by native `fetch`)
  and append a query string to the endpoint that broke the admin-ajax fallback's
  action mapping, so the tool failed on both transports. GET params now travel only
  in the URL query string; `callWordPress` never sets a body on GET/HEAD; and the
  admin-ajax fallback splits the query string off before matching the action and
  forwards the params. (`connectmwp-mcp/index.js`)
- **connectmwp-server — unauthenticated SSRF in `/api/verify-site`.** The site-reachability
  probe fetched any user-supplied host server-side with no private-range checks,
  letting an unauthenticated caller probe the server's internal network and burn
  egress. Added private/loopback/link-local IP blocking (mirrors the MCP client's
  guard), internal-name rejection, pinned the Node.js runtime, and disabled
  redirect-following to prevent rebinding/redirect-to-internal. (`connectmwp-server/src/app/api/verify-site/route.ts`)

### Chore
- Cleaned trivial lint errors in the WIP (`markdown.ts` `let`→`const`, unused catch
  binding in the legal page). Synced server version display strings to 1.2.4.

> Note: `connectmwp-agent` remains at 1.2.3 (unchanged in this pass).
> The earlier security/architecture remediations (open redirect, fragment token
> transmission, atomic nonces, contributor publish checks, IP spoofing, MCP SSRF,
> media size limits, markdown SSOT extraction, typed site-verification errors)
> were verified resolved — see `_internal/REMEDIATION-VERIFICATION_2026-05-26_18-52.md`.
