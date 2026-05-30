# CLAUDE.md

> **Verified against:** connectMWP **v2.0.27** (all three components, lockstep).
> **Last reviewed:** 2026-05-29.
> **Re-verify when:** the request-signing canonical string, the `permission_callback` / `rest_pre_dispatch` filter in the plugin, the on-disk schema of `~/.connectmwp.json` or `~/.connectmwp/<host>.ed25519`, the lockstep versioning rule, or the central-server-out-of-daily-path constraint changes.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

connectMWP (connectmwp.com) is a **decentralized bridge** that lets local AI clients (Claude Desktop/Code, Cursor) publish to self-hosted WordPress sites over MCP. The defining architectural constraint: **no central server sits in the daily traffic path.** The AI client talks straight to the user's WordPress site over HTTPS. The central web app exists only for marketing/onboarding, legal pages, and serving the plugin zip download — it is **not** in the auth or content-publishing path. This is a deliberate decision (security honeypot avoidance, $0 proxy cost, no uptime liability) — see `_internal/concept.md` §5 for the dismissed alternatives, and do not reintroduce a request-proxying server.

## Three components, ONE lockstep version

This repo is a monorepo of three loosely-coupled deliverables. **Project rule: all three carry the same version number, bumped together on every release**, even when only one of them changed. Lockstep matches the project's actual recent release history and avoids the "which component is at which version" confusion that bit earlier work — see memory `connectmwp-auth-architecture` and the Session #2 handover for the explicit Stefan correction that established this rule.

| Dir | What | Lang | Version source |
|-----|------|------|----------------|
| `connectmwp-agent/` | WordPress plugin (signature-verifying gatekeeper that runs on the user's site) | PHP, single file | `Version:` header in `connectmwp-agent.php` |
| `connectmwp-mcp/` | Local MCP client / signer (stdio server the AI client spawns; published on npm as `connectmwp-mcp`) | Node ESM | `version` in `package.json` |
| `connectmwp-server/` | Central web app (marketing, legal pages, plugin zip download; **not** in the daily auth/content path) | Next.js 16 / React 19 | `version` in `package.json` |

The README's setup commands and version references can drift from the source files — **trust the source files (plugin header + two `package.json`s) over any README claim.** **The version Single Source of Truth is the repo-root `/VERSION` file.** Never hand-edit the per-file version literals — run `node scripts/sync-version.mjs` to propagate `/VERSION` into the plugin header + both `package.json`s, and a git pre-commit hook (`scripts/install-hooks.sh`) runs `node scripts/sync-version.mjs --check` to block any commit where they've drifted. The plugin no longer has a `const VERSION`; its UI reads the header at runtime via `get_file_data()`.

## Commands

```bash
# Central server (connectmwp-server/)
cd connectmwp-server
npm run dev      # next dev
npm run build    # next build
npm run lint     # eslint

# MCP client (connectmwp-mcp/) — run directly, no build step.
# Once installed from npm, the recommended entrypoint is `npx -y connectmwp-mcp`.

# Pair a new WordPress site (the only "create" command — also used to UPDATE
# an existing pairing after a key revoke on the WP side):
node connectmwp-mcp/index.js add-site --enroll "https://example.com,<pairing_code>" [--default] [--label "My Site"]

# List, swap default, remove:
node connectmwp-mcp/index.js list-sites
node connectmwp-mcp/index.js set-default --site "https://example.com"
node connectmwp-mcp/index.js remove-site --site "https://example.com"
# With no CLI arg it boots as an MCP stdio server (how the AI client invokes it).

# Token-based add-site (--site + --token) is REJECTED with a hard error in v2 —
# see `connectmwp-mcp/index.js:343`. The only auth model is Ed25519 enrollment.

# WordPress plugin — no build. Packaging is manual:
#   zip connectmwp-agent.zip -r connectmwp-agent/
#   cp connectmwp-agent.zip connectmwp-server/public/connectmwp-agent.zip
# The plugin zip lives at the repo root AND is mirrored under the central
# server's /public/ for download — both copies must stay byte-identical (same
# sha). Both ARE committed to git (not gitignored).
```

There is no automated test suite in any component. The full operational runbook for pairing sites, re-pairing after a key revoke, and publishing a new npm version lives in `OPERATIONS.md` at the repo root.

## How the pieces talk

**Daily runtime path** (`connectmwp-mcp/index.js` → `connectmwp-agent.php`) — **session-less Ed25519 signatures, no login state ever created on the WP side:**

- Client calls `{site}/wp-json/connectmwp/v1/{posts|media|tags|categories}` with four custom auth headers (as of v2.0.19):
  - `X-ConnectMWP-Key: <key_id>` — identifies which paired client is calling.
  - `X-ConnectMWP-Timestamp: <unix_seconds>` — must be within ±300s of the WP server clock.
  - `X-ConnectMWP-Nonce: <rfc4122_uuid_v4>` — fresh `crypto.randomUUID()` per request (v2.0.19+). Closes the replay window by making every signature unique by construction. Plugin rejects missing nonce with `connectmwp_missing_nonce` 401 — distinct from generic signature failure so support can recognize "pinned-old-client" instantly.
  - `X-ConnectMWP-Signature: <base64(ed25519_detached_sig)>` — signature over the canonical string.
  - `X-ConnectMWP-Body-Hash: <sha256_hex>` — REQUIRED on multipart uploads (covers the file bytes since the body itself is the multipart payload). Added in v2.0.10. Without this, the upload path is forgeable; never remove.
- Header names are intentionally custom (NOT `Authorization`) because managed hosts (SiteGround, Kinsta, WP Engine) strip standard `Authorization` headers at the edge proxy before they hit PHP. **Never move auth to a standard header.**
- The canonical signing string is deterministic across both client and plugin (v2.0.19+ — nonce in position 2):
  ```
  timestamp + "\n" + nonce + "\n" + METHOD + "\n" + path + "\n" + sha256_hex(sorted_query) + "\n" + sha256_hex(raw_body_or_empty)
  ```
  Byte-identical reconstruction on the PHP side is the #1 source of interop bugs — pin nonce position (after timestamp, before method), query-string sorting, encoding rules, and `path` (whether to include the `/wp-json` prefix). Run `bash _internal/verify/interop_test.sh` after any change to either side.

- **Admin-AJAX fallback:** if REST returns 401/403/404 or the fetch throws, the client retries the same operation through `wp-admin/admin-ajax.php` (`action=connectmwp_api`, sub-action in `connectmwp_action`). The plugin exposes every capability via *both* REST and AJAX because some hosts lock down REST entirely. The same three signature headers authorize both paths (AJAX signs a synthetic path like `/connectmwp/v1/<action>`). **Any new tool must be wired into both paths** — the REST route + handler in the plugin, the AJAX action mapping in `callWordPressAjax()`, and the AJAX dispatch in the plugin's `handle_ajax_request()`.

**Auth model (plugin side) — never `wp_set_current_user`, never `determine_current_user`:**

- Signature verification runs in a central `rest_pre_dispatch` filter scoped to the `connectmwp/v1` namespace. The `/enroll` endpoint is the **only** exception — it's authorized by a single-use `X-ConnectMWP-Enroll-Code` header instead of a signature, because there's no signing key yet.
- Per-route `permission_callback`s then run capability checks via `user_can($bound_user_id, ...)` — `edit_posts` for read/draft, `publish_posts` for publish, `edit_post`+$post_id for update, `upload_files` for media, `manage_categories` for taxonomy. **No login session is ever established.** The plugin must set `post_author = $bound_user_id` explicitly on writes and must NEVER rely on `get_current_user_id()` (there is no current user). This is the whole reason the product works against 2FA/security plugins — they police login state, and there is none.
- Verification order: HTTPS check → key lookup → timestamp window (±300s) → signature rebuild + verify with `sodium_crypto_sign_verify_detached` → cross-request replay check (`cmwp_sig_<sha256(signature)>` options, ~360s TTL) → per-request static cache (`$signature_verified` — WP invokes `permission_callback` multiple times per request on some hosts, this guard prevents the second invocation from falsely flagging a replay) → capability check → handler.
- **Critical for cache-enabled hosts:** every `connectmwp/v1` response must emit `Cache-Control: no-store, no-cache` + `litespeed_control_set_nocache` (LiteSpeed action). Without these, session-less means WP doesn't auto-emit no-cache and LiteSpeed serves cached signed responses to anonymous callers — a CRITICAL bug found in live testing on 2morrow.ai during Session #2. Closed in v2.0.12; do NOT remove.

**Stored material:**
- WP side, in user meta `_connectmwp_keys` keyed by `key_id`: `public_key` (raw 32-byte, base64), `bound_user_id`, `label`, `created`, `last_used`, `last_ip`. Plus the replay cache (per-`key_id` options) and transient enrollment codes.
- Client side, `~/.connectmwp.json`: `{ defaultSite, sites: { <normalizedUrl>: { key_id, private_key_path, label, updated } } }`. Private key bytes live at `~/.connectmwp/<hostname>.ed25519` (mode `0600`), referenced from the JSON. **The private key never leaves the machine** — only the public key was ever transmitted (during pairing).

**One-time pairing (local, decentralized — replaces the v1 browser-OAuth flow):**

1. Admin opens WP Admin → **Settings → connectMWP** → clicks **Generate Pairing Code**.
2. Plugin mints a single-use enrollment code (10-min TTL, bound to the issuing admin user) and renders a copy-paste terminal command — e.g. `npx -y connectmwp-mcp add-site --enroll "https://site.com,cmwp_enroll_<…>"`. The pairing screen is rendered by the plugin's own standalone view (`render_clean_oauth_screen` — deliberately bypasses `wp_iframe` to avoid third-party plugin markup conflicts).
3. Admin runs the command in their terminal. The MCP client:
   - Generates a fresh Ed25519 keypair locally.
   - Stages the private key to `~/.connectmwp/<host>.ed25519.tmp-<pid>` (mode `0600`).
   - POSTs `{ public_key, label }` to the plugin's `/wp-json/connectmwp/v1/enroll` with `X-ConnectMWP-Enroll-Code: <code>`.
4. Plugin validates the code (single use, unexpired, matches issuing user), stores the public key in user meta under a new `key_id`, returns the `key_id`.
5. **Only on success**, the MCP client `rename`s the staged key into final place and writes the new entry into `~/.connectmwp.json`. A failed re-pair (e.g. expired code) leaves any existing working key intact — this is the v2.0.11 temp-file-then-rename fix; do NOT regress it (memory: `connectmwp-auth-architecture`).

**Central web app (`connectmwp-server`) is OUT of the daily path.** It's still in the repo because it hosts the marketing landing page, legal pages (`/legal/[slug]`), and serves the plugin zip from `/public/connectmwp-agent.zip`. The old `/callback` page from the v1 OAuth flow may still exist in code but is no longer reachable from any v2 pairing flow. Do not put auth or content-publishing logic on the server — that violates the decentralization rule.

## Component-specific gotchas

- **`connectmwp-server` uses Next.js 16** (see its `AGENTS.md`): APIs and conventions differ from older Next.js in your training data. Consult `node_modules/next/dist/docs/` or Context7 before writing Next.js code here. App Router, React 19, Tailwind v4. The legal pages were migrated to Tailwind in v2.0.10; do not reintroduce the old `globals.css` class references (memory + CHANGELOG v2.0.13 entry).
- **`connectmwp-mcp` config** lives at `~/.connectmwp.json`: `{ defaultSite, sites: { <normalizedUrl>: { key_id, private_key_path, label, updated } } }`. URLs are normalized (https:// prefix added, trailing slash stripped) and matched by hostname so protocol/slash differences still resolve. Each tool takes an optional `site` arg; absent it, `defaultSite` is used. There is **no `CONNECTMWP_TOKEN` / `CONNECTMWP_SITE` env-var fallback in v2** — the v1 token fallback was removed. The private key lives separately at `~/.connectmwp/<host>.ed25519` (referenced by `private_key_path`, mode `0600`).
- **`connectmwp-mcp` published name:** `connectmwp-mcp` on the public npm registry as of 2026-05-28. AI clients should be configured with `npx -y connectmwp-mcp`, not absolute file paths. Full release flow (lockstep bump + CHANGELOG + zip repack + `npm publish`) is documented in `OPERATIONS.md` §3.
- **Plugin auth flow lives in a single file**, `connectmwp-agent/connectmwp-agent.php`. The signature verification (`verify_request_signature`), `rest_pre_dispatch` central filter, per-route `permission_callback`s, AJAX dispatch, and pairing screen all live in there. Treat it as the auth boundary — every endpoint must go through `verify_request_signature` (except `/enroll`); never add a route with `permission_callback => '__return_true'` outside the enroll endpoint.
- **Identity-disclosing endpoints (v2.0.15+):** `/enroll` and `/whoami` both return a canonical "identity payload" shaped by `build_identity_payload()` — `{ success, key_id, site:{title,url}, user:{login,display_name,roles}, capabilities:{edit_posts,publish_posts,edit_others_posts,upload_files,manage_categories,delete_posts} }`. `/whoami` is signature-authenticated (via `check_signature_only`, no capability gate) and is used by the MCP client to verify end-to-end signing post-pairing. Keep `/enroll` and `/whoami` shape-identical so both can drive the same CLI/UI summary code.
- **Admin-page pairing-status poll (v2.0.16+):** `pairing_status_handler` is wired to admin-ajax (`action=connectmwp_pairing_status`) — gated by `current_user_can('manage_options')` + nonce, no MCP signature. Returns `{ code_active, expires_in, total_keys, latest_key_id, latest_created, latest_label }`. The settings-page JS polls it every 3s while a pairing code is visible (and immediately on `visibilitychange`), and on detecting a new key flips the pairing card to a success state and reloads. This is admin UX only — keep it off the MCP-client traffic path; never expose the underlying option-read pattern via REST without a signature.
- **`_internal/`** holds `ARCHITECTURE.md` (authoritative v2 design — **read this before touching auth or any plugin/MCP endpoint**), `concept.md` (full product spec; partially v1-drifted on auth specifics — see its banner), `diagnose.py`, audit reports, and snapshots. Reference material, not shipped code. `_internal/` is gitignored.
- **Plugin zip — only ONE of the two locations is committed to git.** The release flow builds two byte-identical copies: `connectmwp-agent.zip` at the repo root (gitignored, local build artifact for Stefan / direct uploads), and `connectmwp-server/public/connectmwp-agent.zip` (committed — this is what serves at `https://connectmwp.com/connectmwp-agent.zip` for end-user downloads). Both must stay sha-identical after every plugin change; only the public mirror lands in git. Implication: a `git clone` of this repo will NOT yield `connectmwp-agent.zip` at the root — devs working from clone must either build it locally or grab the public/ copy.

## Documentation hygiene (project rule, est. 2026-05-28)

**Every persistent doc in this repo must carry a software-version anchor at the top.** Without it, readers cannot tell whether the doc matches the code or has silently drifted across releases. This is a learned-the-hard-way rule: `SUPPORT_TRAINING.md` and earlier parts of this CLAUDE.md described v1 token auth long after v2 shipped, with no signal to the reader that the content was stale.

**Required anchor format** (blockquote at the very top of the doc):

```markdown
> **Verified against:** connectMWP **vX.Y.Z** (all three components, lockstep) — or list per-component if it varies.
> **Last reviewed:** YYYY-MM-DD.
> **Re-verify when:** <the specific code paths or release events whose change would invalidate this doc>.
```

Applies to: `README.md`, `CLAUDE.md`, `OPERATIONS.md`, `SUPPORT_TRAINING.md`, `_internal/ARCHITECTURE.md`, `_internal/FEATURE_NOTES.md`, any future runbook / playbook / training doc.

Exempt: `CHANGELOG.md` (every entry is intrinsically version-dated), per-component `AGENTS.md` files when they declare the component version inline, and **point-in-time `_internal/` artifacts whose filename already encodes the moment of validity** — `SNAPSHOT_*.md`, `PLAN_*.md`, `SECURITY-REVIEW-REPORT_*.md`, `ARCH-REVIEW-REPORT_*.md`, `REMEDIATION-VERIFICATION_*.md`, `_PREV_SESSION_END.md`. These are intentionally frozen-in-time records; their date stamp IS the anchor.

When a doc is found to be drifted (some claims correct, others not) and a rewrite is deferred, prepend an **OUT OF DATE banner** to the anchor listing the specific drifted claims and the authoritative source(s) for current behavior. Do not silently delete or auto-fix prose — flag, then schedule the rewrite.
