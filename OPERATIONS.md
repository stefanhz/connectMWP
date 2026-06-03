# connectMWP — Operations Runbook

> **Verified against:** connectMWP **v2.2.0** (all three components, lockstep).
> **Last reviewed:** 2026-06-02.
> **Re-verify when:** the MCP CLI surface changes (`add-site`/`remove-site`/`set-default`/`list-sites` flags), the plugin auth flow changes, the release/publish process changes, the `connectmwp_trust_proxy` / `CONNECTMWP_TRUST_PROXY` trusted-proxy setting changes, the API-token flow (`/mcp` endpoint, settings card, per-site cap) changes, the ChatGPT OAuth flow (`/connectmwp-oauth/authorize`, `/oauth/token`, the Connected-apps card) changes, or component versions drift out of lockstep.

Project-internal operational guide. **Not user-facing** — for that, see `README.md`.
This file is the Stefan-and-Claude reference for the recurring operational moves:
pairing sites, re-pairing after a key revoke, and shipping a new npm release.

## Contents

1. [Connect a NEW WordPress site](#1-connect-a-new-wordpress-site-this-machine)
2. [UPDATE an existing connection (after revoking the key)](#2-update-an-existing-connection-after-revoking-the-key)
3. [Publish a new version of `connectmwp-mcp` to the npm registry](#3-publish-a-new-version-of-connectmwp-mcp-to-the-npm-registry)
4. [Reference — file locations](#4-reference--file-locations)
5. [Replay-blocked verification (T137 / v2.0.19+)](#5-replay-blocked-verification-t137--v2019)
6. [Local Node↔PHP interop verification (signing-canonical proof)](#6-local-nodephp-interop-verification-signing-canonical-proof)
7. [Local error-sanitization verification (T138)](#7-local-error-sanitization-verification-t138)
8. [Security hardening — edge rate-limiting & trusted proxy](#8-security-hardening--edge-rate-limiting--trusted-proxy)
9. [Connect Antigravity / Gemini CLI / other remote clients (API token)](#9-connect-antigravity--gemini-cli--other-remote-clients-api-token)
10. [Connect ChatGPT via OAuth (v2.2.0+)](#10-connect-chatgpt-via-oauth-v220)

---

## 1. Connect a NEW WordPress site (this machine)

**On the WordPress site:**

1. Log in → **Settings → connectMWP**.
2. Click **Generate Pairing Code**. A one-shot terminal command appears with a 10-minute timer.
3. Copy the command. It looks like:

   ```bash
   npx -y connectmwp-mcp add-site --enroll "https://yourblog.com,cmwp_enroll_<long_random_string>"
   ```

**On this Mac:**

4. Paste and run in any terminal. On success:

   ```
   [INFO] Initiating Ed25519 pairing with WordPress site: https://yourblog.com
   [SUCCESS] Client paired and enrolled successfully! Key ID: cmwp_key_xxxxxxxxxxxxxxxx
   [INFO] Set https://yourblog.com as default target site.   (first site only)
   ```

   Under the hood: fresh Ed25519 keypair generated locally, only the public key
   POSTed to WP, private key stored at `~/.connectmwp/<host>.ed25519` (mode `0600`),
   site added to `~/.connectmwp.json`.

**Optional flags:**

- `--default` — force this site as the new default target (otherwise: auto-default only if no other sites exist).
- `--label "My Personal Blog"` — custom label shown in WP's Paired Clients table. Default is `Local client (<machine-hostname>)`.

**Verify:**

```bash
npx -y connectmwp-mcp list-sites      # new site listed
```

WP side: **Settings → connectMWP → Paired Clients** now shows a row with the new `cmwp_key_...` ID.

**Failure modes:**

- `[ERROR] Pairing failed: enrollment code expired / used` → generate a new code (codes are one-shot, 10-min). Your existing key (if any) for this site is **safe** — the v2.0.11 fix uses temp-file + rename, so failed re-pairs do not destroy a working key.
- `[ERROR] Pairing failed: HTTP 401` → plugin not active on the WP site, or `connectmwp` REST namespace is being blocked by a host firewall.

---

## 2. UPDATE an existing connection (after revoking the key)

**There is no separate `update` / `re-enroll` command.** Re-running `add-site --enroll`
with the same site URL safely overwrites both the local config entry and the
private key file (temp-file + rename — failed re-pair preserves the working key).

**Steps after revoking a key on WP** (e.g., `cmwp_key_3a661f1bc68cb205`):

1. WP Admin → **Settings → connectMWP** → click **Generate Pairing Code** again
   (revoked keys can never be reused; you always mint a new one). New 10-minute one-shot command appears.

2. On this Mac, run the new command:

   ```bash
   npx -y connectmwp-mcp add-site --enroll "https://2morrow.ai,cmwp_enroll_<new_code>"
   ```

3. Success message shows the **new** `Key ID:` (fresh `cmwp_key_...`).

**Result:**

- `~/.connectmwp.json` entry for the site → overwritten with the new `key_id`.
- `~/.connectmwp/<host>.ed25519` → overwritten with the new private key.
- WP-side: a NEW row in Paired Clients. The revoked row stays in its revoked
  state until you manually delete it (cosmetic; revoked keys cannot authenticate).
- Old (revoked) key is dead independently of any local action.

**You do NOT need to `remove-site` first.** Doing so before re-pair only deletes
the JSON config entry; the dangling private key file at `~/.connectmwp/<host>.ed25519`
stays until the next re-enroll overwrites it.

---

## 3. Publish a new version of `connectmwp-mcp` to the npm registry

**Pre-conditions:**

- `npm whoami` prints your npm username (no re-login needed; auth persists in `~/.npmrc`).
- If it errors with `ENEEDAUTH` → `npm login` first.

**The full release flow** (project rule: **lockstep all three components**, even if only one changed):

### Step 1 — Make code changes

Edit `connectmwp-mcp/index.js` (or `connectmwp-server/...` or `connectmwp-agent/connectmwp-agent.php`) as needed.

### Step 2 — Bump the version (ONE place — the `/VERSION` file)

The version Single Source of Truth is the repo-root **`/VERSION`** file (since v2.0.25). Edit it, then propagate with the sync script — never hand-edit the per-file version literals:

```bash
echo "2.0.X" > VERSION                 # the ONLY version you hand-edit
node scripts/sync-version.mjs          # writes it into both package.json files + the plugin Version: header
node scripts/sync-version.mjs --check  # gate: exits non-zero on any drift
```

The plugin no longer carries a `const VERSION` — its settings UI reads its own header at runtime via `get_file_data()`, so there is nothing else to touch. A git pre-commit hook runs `--check` and BLOCKS any commit where the literals have drifted; install it once per clone with `bash scripts/install-hooks.sh`. (Doc `Verified against:` anchors + README version mentions are deliberately NOT script-managed — refresh those in Step 3 / the doc-review step.)

Semver guidance: patch for fixes/tweaks/config; minor for new features; major for breaking changes.

### Step 3 — Prepend a CHANGELOG entry (NEVER edit existing entries)

Top of `CHANGELOG.md`, matching the existing pattern:

```markdown
## 2026-MM-DD — v2.0.X

### Fixed   (or ### Added / ### Changed / ### Removed / ### Verified (live))
- **connectmwp-mcp — <plain-English description of what changed and why>.** Details… (`connectmwp-mcp/index.js`)

### Bumped
- All three components → 2.0.X (lockstep).
```

If the agent changed, also note: `Plugin re-packaged.`

### Step 4 — If the plugin changed, repackage the zip (TWO locations must stay identical)

```bash
cd /Users/stefanhz/Documents/aiSpace/connectMWP
# The zip's top folder must be `connectmwp/` (= the wp.org slug / installed folder),
# but the source working dir is `connectmwp-agent/`, so stage it first.
rm -rf /tmp/cmwp_build && mkdir -p /tmp/cmwp_build/connectmwp
cp connectmwp-agent/connectmwp-agent.php connectmwp-agent/readme.txt /tmp/cmwp_build/connectmwp/
( cd /tmp/cmwp_build && zip -rqX connectmwp.zip connectmwp/ )
cp /tmp/cmwp_build/connectmwp.zip ./connectmwp.zip
cp ./connectmwp.zip connectmwp-server/public/connectmwp.zip
shasum connectmwp.zip connectmwp-server/public/connectmwp.zip   # must match
```

### Step 5 — Preview the npm tarball

```bash
cd /Users/stefanhz/Documents/aiSpace/connectMWP/connectmwp-mcp
npm pack --dry-run
```

Expect exactly **7 files** (as of v2.0.25, after the `lib/` modularization):
`README.md`, `index.js`, `lib/constants.js`, `lib/crypto.js`,
`lib/projections.js`, `lib/validators.js`, `package.json`. All four `lib/*.js`
modules are imported by `index.js` (lines 27–31) and MUST ship — without them the
published package crashes on launch with a module-not-found error. The `files`
allowlist in `package.json` (`index.js`, `lib/**`, `README.md`) is what controls
this. If anything *outside* that set appears (`node_modules`, `*.tmp`,
`package-lock.json`, stray `*.ed25519`) — STOP, fix the `files` field, re-run.

### Step 6 — Publish

```bash
npm publish
```

2FA prompt → 6-digit code from authenticator → success:

```
+ connectmwp-mcp@2.0.X
```

(`--access public` was only needed on the first publish; harmless to include now.)

### Step 7 — Verify it's live (~10s for registry propagation)

```bash
npm view connectmwp-mcp version
# → 2.0.X
```

### Step 8 — Force Claude Desktop to pick up the new version (if needed)

`npx -y` re-resolves on each launch, so usually nothing is needed. If the old
version is stuck:

```bash
rm -rf ~/.npm/_npx/*/node_modules/connectmwp-mcp 2>/dev/null
```

Then ⌘Q + relaunch Claude Desktop.

### Step 9 — Architectural / feature docs (if applicable)

Per the global completion discipline:

- Architectural impact → update `_internal/ARCHITECTURE.md`.
- User-facing behavior change → update `_internal/FEATURE_NOTES.md`.

### Step 10 — Commit and push (only when Stefan says)

Clean order: bump → CHANGELOG → publish → commit → push.

**Common failure modes:**

| Error | Cause | Fix |
|---|---|---|
| `403 Forbidden — You cannot publish over the previously published versions: 2.0.X` | Forgot to bump | Bump version, re-publish. npm never allows republishing the same version. |
| `EOTP — npm requires a one-time password` | 2FA prompt | Type the 6-digit code. |
| `E404` on `npm view` immediately after publish | Registry propagation lag | Wait 10–30s, retry. |
| Working tree dirty after publish but plugin zip wasn't re-built | Forgot Step 4 | Run Step 4. |

**Don't:**

- Don't `npm unpublish` a version you've shipped (allowed for 72 hours but breaks anyone who installed it). Treat publishes as permanent — fix forward with a new version.
- Don't publish without bumping all three components in lockstep.
- Don't edit existing CHANGELOG entries to "consolidate" — entries are immutable history.

---

## 4. Reference — file locations

| What | Where |
|---|---|
| Local site config (all paired sites) | `~/.connectmwp.json` |
| Local Ed25519 private key per site | `~/.connectmwp/<hostname>.ed25519` (mode 0600) |
| MCP client source | `connectmwp-mcp/index.js` |
| MCP client published name | `connectmwp-mcp` (public npm registry) |
| WP plugin source | `connectmwp-agent/connectmwp-agent.php` |
| WP plugin zip (master) | `connectmwp.zip` (root; internal folder `connectmwp/`) |
| WP plugin zip (download mirror) | `connectmwp-server/public/connectmwp.zip` (must match master sha) |
| Central web app | `connectmwp-server/` (Next.js 16) |
| Architecture doc | `_internal/ARCHITECTURE.md` |
| Changelog (immutable, append at top) | `CHANGELOG.md` |
| Task tracker | `_internal/TASKS.md` |

---

## 5. Replay-blocked verification (T137 / v2.0.19+)

**Goal:** Prove a captured signed request cannot be replayed against a paired
WordPress site. Run after deploying a v2.0.19+ plugin and a v2.0.19+ MCP
client to a paired site (e.g. `https://2morrow.ai`).

**Prerequisites:**
- A site paired with a v2.0.19+ plugin installed and active.
- A v2.0.19+ MCP client locally with that site's pairing in `~/.connectmwp.json`.
- `curl`, `jq` available.

### Step 1 — Capture a legitimate request

Add a one-line debug log to `connectmwp-mcp/index.js` right before the
`fetch(url, ...)` in `callWordPress`:

```js
console.error('CAPTURE:', JSON.stringify({ url, headers }));
```

Run one tool invocation from the AI client (e.g. ask Claude to "list categories
on 2morrow.ai"). Grab the line from the MCP server's stderr (Claude Desktop:
`~/Library/Logs/Claude/mcp-server-connectmwp.log` or wherever your client
writes MCP stderr). Remove the debug line afterward.

### Step 2 — Replay the captured headers via curl (REST path)

Within ~5 seconds of capture (well inside the 300s skew window):

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
     -H "X-ConnectMWP-Key: <captured>" \
     -H "X-ConnectMWP-Timestamp: <captured>" \
     -H "X-ConnectMWP-Nonce: <captured>" \
     -H "X-ConnectMWP-Signature: <captured>" \
     https://2morrow.ai/wp-json/connectmwp/v1/categories
```

**Expected:** `HTTP 401`. To see the specific WP_Error code:

```bash
curl -s \
     -H "X-ConnectMWP-Key: <captured>" \
     -H "X-ConnectMWP-Timestamp: <captured>" \
     -H "X-ConnectMWP-Nonce: <captured>" \
     -H "X-ConnectMWP-Signature: <captured>" \
     https://2morrow.ai/wp-json/connectmwp/v1/categories | jq .code
```

**Expected:** `"connectmwp_replay_detected"` (the sig-hash cache catches the
second use of the same signature) — OR — if you wait > 360s (cache TTL) the
replay rejection drops; that's an out-of-window case, not the attack.

### Step 3 — Replay against the AJAX fallback path

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
     -X POST \
     -H "X-ConnectMWP-Key: <captured>" \
     -H "X-ConnectMWP-Timestamp: <captured>" \
     -H "X-ConnectMWP-Nonce: <captured>" \
     -H "X-ConnectMWP-Signature: <captured>" \
     --data 'action=connectmwp_api&connectmwp_action=get_categories' \
     https://2morrow.ai/wp-admin/admin-ajax.php
```

**Expected:** `HTTP 401`.

### Step 4 — Hard-cut probe (proves a pre-v2.0.19 client is rejected)

Send a signature-shaped but nonce-less request:

```bash
curl -s \
     -H "X-ConnectMWP-Key: anything" \
     -H "X-ConnectMWP-Timestamp: $(date +%s)" \
     -H "X-ConnectMWP-Signature: AA==" \
     https://2morrow.ai/wp-json/connectmwp/v1/categories | jq .code
```

**Expected:** `"connectmwp_missing_nonce"` (the distinct code that lets
support recognize a pinned-old-client at a glance).

### What "pass" looks like

Steps 2, 3, 4 all return 401. The `.code` field clearly distinguishes
"replay caught" vs "old client". **If any step returns 200 with category
data, STOP — the replay window is open. Do not declare T137 closed until the
plugin is investigated.**

---

## 6. Local Node↔PHP interop verification (signing-canonical proof)

Without spinning up a WordPress install, prove the Node signer and the PHP
verifier construct byte-identical canonical strings (the #1 implementation
risk per ARCHITECTURE.md §10).

```bash
bash _internal/verify/interop_test.sh
```

**Expected output:**

```
[node] keypair generated
[node] pub_key_b64=...
[node] signature=...
[php]  INTEROP_VERIFIED
[ac1]  signatures differ across nonces (uniqueness proven)
[det]  signature is deterministic (replay would be caught by sig-hash cache)

INTEROP VERIFIED — T137 byte-identical across Node/PHP
```

Exits non-zero on any divergence. Run after every change to the canonical
shape on EITHER side.

---

## 7. Local error-sanitization verification (T138)

Force three signing-failure modes and assert the user-facing message has no
filesystem path, while stderr keeps the full operator diagnostic.

```bash
bash _internal/verify/sanitization_test.sh
```

**Expected output:**

```
--- user-facing output ---
USER:A: Failed to sign request — private key file not found. ...
USER:B: Failed to sign request — private key file not readable ...
USER:C: Failed to sign request — private key could not be parsed. ...

--- operator (stderr) output ---
[connectmwp:diag] ... REST signing failed keyPath=/Users/.../<host>.ed25519 ...
[connectmwp:diag] ... AJAX signing failed keyPath=/Users/.../<host>.ed25519 ...
[connectmwp:diag] ... REST signing failed keyPath=/Users/.../<host>.ed25519 ...

=== assertions ===
  AC1/AC2 PASS — user output has no filesystem path
  AC3 PASS — user output includes recovery command
  AC4 PASS — operator diagnostic kept full path + tag

T138 SANITIZATION VERIFIED
```

Exits non-zero on any leak. Run after any change to throw sites in
`connectmwp-mcp/index.js`.

### P8 error-handling notes (v2.0.28)

- **Diagnosing a generic "Tool execution failed" report.** As of v2.0.28 the
  AI client only sees `Tool execution failed — see local connectMWP
  diagnostics (stderr).` for any unrecognized tool error — the real cause
  (message, error code, stack) is on the `[connectmwp:diag] ... tool-error
  tool=<name> ...` line in the spawning client's captured stderr. Grep that
  log for `tool-error`.
- **`list-sites` shows nothing unexpectedly.** v2.0.28 distinguishes the
  cases: a genuinely missing `~/.connectmwp.json` (first run) is silent; a
  **corrupt** file no longer silently hides your sites — the CLI prints
  `connectMWP: ~/.connectmwp.json is present but unreadable (invalid JSON).
  Your paired sites are NOT lost — fix or restore the file.` and emits a
  `[connectmwp:diag] config-corrupt` line; an unreadable file (permissions)
  emits `[connectmwp:diag] config-read-error`. Grep stderr for `config-` to
  tell a corrupt/locked file apart from a true first run.
- Coverage: `bash _internal/verify/tool_error_sanitization_test.sh` and
  `bash _internal/verify/config_error_classes_test.sh`.

---

## 8. Security hardening — edge rate-limiting & trusted proxy

> Added in v2.0.26 (P6 / T041). The `/enroll` endpoint is the only request the
> plugin accepts without a signature, so it carries its own abuse controls. This
> section explains the in-plugin controls and the edge control you should pair
> with them.

### 8.1 Edge rate-limiting (the primary control)

The plugin includes a per-IP enrollment limiter (5 attempts / 10 minutes), and
as of v2.0.26 it no longer writes any database row for structurally-malformed or
missing codes — a flood of garbage `X-ConnectMWP-Enroll-Code` values creates
**zero** `wp_options` rows. That closes the unbounded-write vector.

It is still defense-in-depth, not the whole defense: an attacker rotating across
many **real** source IPs can only be capped at the edge, because the in-plugin
limiter can only meter what it can attribute to a single IP. **Rate-limit
`POST /wp-json/connectmwp/v1/enroll` at the web server / WAF / CDN.** Examples:

- **Nginx** (in the server block):
  ```nginx
  limit_req_zone $binary_remote_addr zone=cmwp_enroll:10m rate=10r/m;
  location = /wp-json/connectmwp/v1/enroll {
      limit_req zone=cmwp_enroll burst=5 nodelay;
      try_files $uri $uri/ /index.php?$args;
  }
  ```
- **Cloudflare**: Security → WAF → Rate limiting rules → match URI Path equals
  `/wp-json/connectmwp/v1/enroll`, threshold e.g. 10 requests / 1 minute per IP,
  action Block for 10 minutes.
- **fail2ban**: a jail watching the access log for repeated `POST .../enroll`
  responses (401/429) from one IP.

### 8.2 "Behind trusted proxy" setting

By default the plugin reads the client IP from the direct connection
(`REMOTE_ADDR`), which cannot be spoofed. If this site genuinely sits behind a
reverse proxy / CDN you control (Cloudflare, Nginx, a load balancer), the direct
connection is the proxy, so you may want the plugin to attribute the limiter to
the real client IP from the forwarding headers instead.

Turn it on **only if** the statement above is true for your site.

**Via the admin UI:**
1. Log in to WordPress as an administrator.
2. Go to **Settings → connectMWP**.
3. Scroll to the **Network & security** card.
4. Tick **"This site is behind a trusted reverse proxy / CDN"**.
5. Click **Save setting**. You should see "Trusted-proxy setting saved."

**Via `wp-config.php` (infra-as-code, overrides the UI setting):**
```php
define('CONNECTMWP_TRUST_PROXY', true);
```
Place this line above the `/* That's all, stop editing! */` comment. When the
constant is defined it wins over the admin checkbox (the checkbox is shown
disabled, reflecting the forced value).

- **OFF (default):** client IP = `REMOTE_ADDR` — un-spoofable.
- **ON:** client IP = the **last** hop of `X-Forwarded-For` (the value your
  trusted proxy appended), or `X-Real-IP`; if those are absent/invalid it falls
  back to `REMOTE_ADDR` — it never trusts a forged value.

**Warning:** enabling this while the site is **not** actually behind a controlled
proxy lets a caller spoof their IP via `X-Forwarded-For`, evading the per-IP
limiter. When in doubt, leave it OFF and rely on the edge rate-limit in §8.1.

---

## 9. Connect Antigravity / Gemini CLI / other remote clients (API token)

Remote MCP clients that support a custom `Authorization: Bearer` header
authenticate with a per-site API token. No central server is involved — the
`/mcp` endpoint runs on the user's own site. This flow is entirely admin-side
on WordPress + a paste into the client; there is no `connectmwp-mcp` CLI step.

**On the WordPress site:**

1. Log in → **Settings → connectMWP** → find the **API token** card.
2. Pick the **WP user the token binds to** — the client will act with exactly
   that user's capabilities (post author = that user, caps checked via
   `user_can(bound_user, …)`). Choose a user with no more than the access needed
   (an Author or Editor, not necessarily an Administrator).
3. Optionally set a **label** (shown in the token list so you can tell connectors
   apart), then click **Generate**.
4. The plaintext token (`cmwp_cgpt_<hex>`) is shown **once** — it is stored only
   as a sha256 hash and can never be re-displayed. Copy it now along with the
   **connector URL** the card displays.

**In your remote MCP client (Antigravity, Gemini CLI, or similar):**

5. Add a new remote MCP server.
6. Set the **server URL** to the connector URL from the card
   (`https://yoursite.com/wp-json/connectmwp/v1/mcp`).
7. Set **authentication** to **Bearer token** (also labelled "API key" in some
   clients) and paste the `cmwp_cgpt_<hex>` token.
8. **If your host strips the `Authorization` header** (some managed hosts do),
   you can fall back to the **path-token URL** — the token embedded as a path
   segment: `https://yoursite.com/wp-json/connectmwp/v1/mcp/cmwp_cgpt_<hex>` —
   with the auth field left empty. **This fallback is OFF by default and must be
   explicitly enabled.** In WP Admin, tick **"Enable URL-embedded token
   fallback"** in the API token card; only then does the card surface the
   path-token URL and only then does the plugin honor a token in the URL.
   **Log-exposure warning:** the URL-embedded form puts your token in the
   address, so it can appear in server/CDN access logs. Use it only if the
   header method genuinely fails, and **rotate the token periodically** (revoke
   + regenerate). The two header methods (`Authorization: Bearer` and
   `X-ConnectMWP-Token`) always work and do not require this opt-in.
9. Save. The client runs `initialize` → `tools/list`; you should see the
   connectMWP tools (create/update/publish posts, tags, categories).

**Multiple sites:** add one server entry per site and give each a distinct name
(e.g. `connectmwp-myblog`) so tools do not get mixed up across sites.

**What these clients can and cannot do:**

- CAN: create / update / publish posts, manage tags and categories, set a post's
  featured image by **media id** (`featured_media`).
- CANNOT: **upload media.** `connectmwp_upload_media` is multipart-only and is
  not exposed over the MCP/JSON-RPC path. To add images, upload them via a
  local client (Claude/Cursor over the stdio signature path) or the WP media
  library, then reference the media id from the remote client.

**Limits & lifecycle:**

- **Per-site cap: 20 live tokens.** To mint a 21st you must revoke an existing
  one first.
- **Revoke** from the same card — find the token row (by label / last-used) and
  click **Revoke**. Revocation is immediate and irreversible; the client will
  get a 401 on the next call. Treat a token like a WordPress Application
  Password: if it leaks, revoke it.
- HTTPS is enforced; the endpoint is per-IP rate-limited. Tokens record a
  last-used timestamp so you can spot stale ones.

---

## 10. Connect ChatGPT via OAuth (v2.2.0+)

ChatGPT's connector UI offers only OAuth, No-Auth, and Mixed authentication
modes — there is no API-key field. ConnectMWP's plugin acts as its own OAuth
2.1 Authorization Server directly on your site, so no central server is
involved. The admin approves the connection via a browser sign-in, and
subsequent access/refresh tokens are issued directly by the plugin.

This flow is browser-based (ChatGPT → browser → your site → back to ChatGPT);
there is no terminal command.

**Steps:**

1. In ChatGPT, open **Settings → Apps (Connectors)**, enable Developer mode,
   and create a new connector.
2. Set the **connector URL** to `https://yoursite.com/wp-json/connectmwp/v1/mcp`.
3. Set **Authentication** to **OAuth**.
4. Click **Sign in**. You will be redirected to your site's login screen — sign
   in as an **administrator** (only administrators can approve OAuth connections).
5. On the consent screen, review the requested access and click **Approve**.
6. ChatGPT completes the OAuth exchange and the connection is live. The session
   appears in WP Admin → **Settings → connectMWP → Connected apps (OAuth)**.

**Multiple sites:** add one connector per site in ChatGPT.

**What ChatGPT can and cannot do:**

- CAN: create / update / publish posts, manage tags and categories, set a post's
  featured image by **media id** (`featured_media`).
- CANNOT: **upload media.** Same multipart limitation as the API-token path.
  Upload via a local client or the WP media library, then reference the id from
  ChatGPT.

**Revoke a ChatGPT connection:**

1. WP Admin → **Settings → connectMWP → Connected apps (OAuth)**.
2. Find the ChatGPT row (App column shows `chatgpt.com`) and click **Revoke**.
3. Revocation is immediate — ChatGPT will receive a 401 on its next request.

**Lifecycle notes:**

- Access tokens expire after 1 hour; the refresh token keeps the connection
  alive for up to 30 days of inactivity. Each time the refresh token is used,
  it is rotated (OAuth 2.1 requirement for public clients).
- An "Expired" status in the Connected apps card means the refresh token has
  lapsed; the user must re-authorize by clicking Sign in in ChatGPT again.
- The OAuth authorization page (`/connectmwp-oauth/authorize`) is a cookie-native
  front-end page — it requires the admin to be logged into WordPress in the same
  browser. It is NOT a REST route, which is why cookie auth works without a REST
  nonce (a browser OAuth redirect cannot supply one).
