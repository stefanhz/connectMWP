# connectMWP — Operations Runbook

> **Verified against:** connectMWP **v2.0.31** (all three components, lockstep).
> **Last reviewed:** 2026-05-29.
> **Re-verify when:** the MCP CLI surface changes (`add-site`/`remove-site`/`set-default`/`list-sites` flags), the plugin auth flow changes, the release/publish process changes, the `connectmwp_trust_proxy` / `CONNECTMWP_TRUST_PROXY` trusted-proxy setting changes, or component versions drift out of lockstep.

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
rm connectmwp-agent.zip connectmwp-server/public/connectmwp-agent.zip
zip -r connectmwp-agent.zip connectmwp-agent/
cp connectmwp-agent.zip connectmwp-server/public/connectmwp-agent.zip
shasum connectmwp-agent.zip connectmwp-server/public/connectmwp-agent.zip   # must match
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
| WP plugin zip (master) | `connectmwp-agent.zip` (root) |
| WP plugin zip (download mirror) | `connectmwp-server/public/connectmwp-agent.zip` (must match master sha) |
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
