# connectMWP — Operations Runbook

> **Verified against:** connectMWP **v2.0.15** (all three components, lockstep).
> **Last reviewed:** 2026-05-28.
> **Re-verify when:** the MCP CLI surface changes (`add-site`/`remove-site`/`set-default`/`list-sites` flags), the plugin auth flow changes, the release/publish process changes, or component versions drift out of lockstep.

Project-internal operational guide. **Not user-facing** — for that, see `README.md`.
This file is the Stefan-and-Claude reference for the recurring operational moves:
pairing sites, re-pairing after a key revoke, and shipping a new npm release.

## Contents

1. [Connect a NEW WordPress site](#1-connect-a-new-wordpress-site-this-machine)
2. [UPDATE an existing connection (after revoking the key)](#2-update-an-existing-connection-after-revoking-the-key)
3. [Publish a new version of `connectmwp-mcp` to the npm registry](#3-publish-a-new-version-of-connectmwp-mcp-to-the-npm-registry)
4. [Reference — file locations](#4-reference--file-locations)

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

### Step 2 — Bump versions in all THREE locations

| File | Field | Format |
|---|---|---|
| `connectmwp-mcp/package.json` | `"version"` | `"2.0.X"` |
| `connectmwp-server/package.json` | `"version"` | `"2.0.X"` |
| `connectmwp-agent/connectmwp-agent.php` | `Version:` header (top of file, ~line 6) | `2.0.X` |

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

Expect exactly **3 files**: `README.md`, `index.js`, `package.json`. If anything
else appears (`node_modules`, `*.tmp`, `package-lock.json`) — STOP, fix the
`files` field in `package.json`, re-run.

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
