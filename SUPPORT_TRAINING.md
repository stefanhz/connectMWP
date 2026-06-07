# connectMWP Support Training & Troubleshooting Manual

> **Verified against:** connectMWP **v2.3.10** (all three components, lockstep).
> **Last reviewed:** 2026-06-07.
> **Re-verify when:** any connection method changes (stdio pairing, API-token flow, or ChatGPT OAuth), the signature/auth headers, capability scoping, REST/AJAX fallback behavior, the Settings → connectMWP page layout, or any user-visible error message changes.

This document gives customer support agents (and any AI support bot trained on this material) the technical background, security context, and troubleshooting steps needed to resolve customer inquiries. It describes the **v2 architecture** — session-less authentication with **three connection methods** depending on the customer's AI client. Any reference you see in older notes to v1 "tokens" (`connectmwp_tk_...`) or a browser-based OAuth handshake *that ran on connectmwp.com* is from the obsolete v1 design and should be ignored. (The v2 ChatGPT OAuth in §2C is different — it runs on the customer's *own* WordPress site, not a central server.)

---

## 1. Core Architecture & Philosophy

connectMWP is a **decentralized bridge** between a user's AI client and their self-hosted WordPress site.

### Key Concept: No Central Server in the Daily Path

Unlike typical integration services (e.g. Zapier), **no central server sits in the traffic path for daily publishing operations.** The AI client talks straight to the customer's WordPress site over HTTPS. `connectmwp.com` exists only as marketing/onboarding and to host the downloadable plugin zip — once a customer is connected, the central site is **never contacted** during normal publishing.

```
[ AI Client ] <--- direct HTTPS, authenticated per-request ---> [ User's WordPress Site ]
                                                                 (verifies auth, no login session)
```

This holds for **all three** connection methods below — including ChatGPT OAuth, where the OAuth server is the customer's *own* WordPress plugin, not a connectMWP server.

### Support Insight: Security Shield

If a customer asks about data privacy or server uptime:

* **Zero-Knowledge:** We do not collect, store, or ever see the customer's WordPress credentials, database, posts, or private signing key. For the stdio method, the private key is generated on the customer's machine during pairing and never leaves it.
* **Compromise Immunity:** Even if `connectmwp.com` goes offline or is compromised, customer publishing pipelines are unaffected — nothing in the daily path touches it.
* **2FA / Security-Plugin Friendly:** connectMWP authenticates each request without ever creating a WordPress **login session**, so security plugins like Wordfence, Solid Security, miniOrange, and WP 2FA have no login event to intercept or revoke — by design. This is true across all three methods.

---

## 2. The Three Connection Methods

Which method a customer uses is determined by **their AI client**, not by preference. A customer can use more than one (e.g. Claude via pairing + ChatGPT via OAuth on the same site).

| Method | For which clients | How auth works | Set up by |
|---|---|---|---|
| **A. Stdio + Ed25519 pairing** | Claude Desktop, Claude Code, Cursor, Cline | Local signed requests (private key on the customer's machine) | One-time terminal pairing command per site |
| **B. API token (Bearer)** | Antigravity, Gemini CLI, other remote MCP clients that support a custom auth header | A per-site bearer token (`cmwp_cgpt_…`) the customer pastes into the client | Generate a token in WP Admin, paste it into the client |
| **C. ChatGPT OAuth 2.1** | ChatGPT | The plugin acts as its own OAuth server; the customer signs in as admin and approves | Add a connector in ChatGPT, sign in, approve consent — no token pasted |

> **All three settle in WP Admin → Settings → connectMWP.** That page is a **client-first switchboard**: three client-family tabs (Claude·Cursor·Cline / ChatGPT / Antigravity·Gemini·other) for setup, plus **one merged "Your connections" table** listing every active connection regardless of method (with a **Type** column and a **per-row Revoke** button). When a customer says "is it connected?" or "how do I disconnect X?", that table is the answer.

### 2A. Stdio + Ed25519 pairing (Claude / Cursor / Cline)

* The AI client spawns a local MCP server process (`connectmwp-mcp`, run via `npx -y connectmwp-mcp`) and talks to it over stdio.
* That local server signs **every** request with the customer's Ed25519 private key and sends it directly to the WordPress REST API.
* Setup is two steps: register the server once per machine, then pair each site once. See §3 (multi-site) and §4 (security mechanism) for the details and the pairing flow.

### 2B. API token (Antigravity, Gemini CLI, other header-capable remote clients)

* The plugin hosts a remote MCP endpoint at `POST /wp-json/connectmwp/v1/mcp`. The client authenticates with a per-site bearer token.
* **Setup:** WP Admin → Settings → connectMWP → **API token** card → choose the WordPress user the client will act as, optionally label it, **Generate token**. The token (`cmwp_cgpt_<hex>`) is **shown once** and cannot be recovered — if lost, revoke and generate a new one. The customer pastes it into their client as `Authorization: Bearer <token>` alongside the connector URL.
* **Per-site cap: 20 tokens.** Revoke unused ones from the same card (and they appear in the merged "Your connections" table).
* **If the host strips `Authorization`:** there is an opt-in (off by default) URL-embedded-token fallback — the token rides in the URL path (`/mcp/<token>`) instead of a header. Warn customers that URL-embedded tokens can show up in server/CDN access logs; they should rotate periodically and **revoke immediately if they suspect the URL was logged or shared**.
* **Blast radius:** a token is roughly equivalent to a WordPress Application Password for the bound user on that one site. The Ed25519 stdio path remains the stronger, replay-protected channel.
* **Media upload is NOT available over this path** (it is multipart-only). A `connectmwp_upload_media` call over the remote endpoint returns a clear "not supported, use a local client" message.

### 2C. ChatGPT OAuth 2.1

* **Why OAuth and not a token?** ChatGPT's connector UI offers only OAuth / No-Auth / Mixed — there is **no API-key field**. So the plugin acts as its own OAuth 2.1 Authorization + Resource Server, directly on the customer's site (no central server).
* **Setup (customer side):** In ChatGPT → Settings → Apps (Connectors), enable Developer mode, create a connector, set the URL to `https://<site>/wp-json/connectmwp/v1/mcp`, set Authentication to **OAuth**, click **Sign in** → they're sent to their own site's login → sign in as an **administrator** → review and **Approve** on the consent screen.
* **Disconnecting:** WP Admin → Settings → connectMWP → the ChatGPT tab / the merged "Your connections" table → **Revoke** (Type = OAuth).
* **Media upload is NOT available** to ChatGPT (it can't send multipart over the remote endpoint).
* Access tokens are `cmwp_oat_…` internally; the customer never sees or pastes them.

---

## 3. The Multi-Site System

connectMWP supports managing multiple WordPress sites. How that's stored depends on the method:

* **Stdio method (A):** all site records live in the customer's home directory and are managed via the CLI.
* **API-token (B) and ChatGPT OAuth (C):** "multi-site" means adding one connector/token **per site** in the client (Antigravity/Gemini/ChatGPT). There is no local `~/.connectmwp.json` for these methods — each site is a separate connector entry in the client, and each site's WP Admin shows that connection in its "Your connections" table.

### Stdio configuration storage

* **JSON config:** `~/.connectmwp.json` (Windows: `%USERPROFILE%\.connectmwp.json`). Stores each site URL, its `key_id`, the path to the private key, an optional label, and a `defaultSite` reference. Mode `0600`.
* **Private keys:** `~/.connectmwp/<hostname>.ed25519` per paired site, mode `0600`. These are sensitive — treat them like SSH private keys; do **not** ask customers to share their contents in tickets.

### Stdio support scenarios

* **How the AI knows which site to edit:** tools accept an optional `site` parameter (e.g. `connectmwp_create_post(site: "blog.com", ...)`). If omitted, the tool uses `defaultSite`.

* **Managing sites via CLI** (walk customers through these local terminal commands):

  | Action | Command |
  |---|---|
  | List linked sites | `npx -y connectmwp-mcp list-sites` |
  | Add/Update a site (pair) | `npx -y connectmwp-mcp add-site --enroll "<site_url>,<pairing_code>" [--default] [--label "<friendly name>"]` |
  | Change default site | `npx -y connectmwp-mcp set-default --site "https://blog.com"` |
  | Remove a site from config | `npx -y connectmwp-mcp remove-site --site "https://blog.com"` |

* **Adding a site requires a pairing code** generated in WP Admin → **Settings → connectMWP → Generate Pairing Code** (Claude·Cursor·Cline tab). Codes are single-use and expire after 10 minutes. The same `add-site --enroll` command both (a) connects a new site and (b) re-connects a site whose key was revoked — there is no separate "update" command. Re-pairing safely overwrites the existing local key and config entry (temp-file + rename, so a failed re-pair never destroys a working key).

* **Removing a site** via `remove-site` only deletes the local JSON entry; it does **not** revoke the key on the WP side and does **not** delete the local private key file. To fully decommission a pairing, the customer should also revoke the connection in WP Admin → Settings → connectMWP → "Your connections".

---

## 4. Security Mechanism (Safe for Support Staff)

When customers experience authentication issues, they are often triggering one of these protections.

### Stdio (A): custom authentication headers (edge-proxy survival)

Every signed request carries these custom HTTP headers:

| Header | Purpose |
|---|---|
| `X-ConnectMWP-Key` | The `key_id` of the paired client making the request |
| `X-ConnectMWP-Timestamp` | Unix epoch seconds (must be within ±300s of the WP server clock) |
| `X-ConnectMWP-Nonce` | A fresh per-request UUID (since v2.0.19) — makes every signature unique, closing the replay window |
| `X-ConnectMWP-Signature` | Base64-encoded Ed25519 detached signature over the canonical request |
| `X-ConnectMWP-Body-Hash` *(uploads only)* | SHA-256 of the multipart file payload — prevents upload tampering |

**Why custom headers?** Managed hosts (Kinsta, SiteGround, WP Engine, etc.) and many WAFs strip the standard `Authorization` header at the edge before it reaches PHP. Custom headers bypass that cleanly. (The API-token method (B) *does* use `Authorization: Bearer` — which is why it has the URL-path fallback for hosts that strip it; see §2B.)

### Replay attack protection (stdio path)

* **Clock skew window:** the timestamp must match the WordPress server clock within **5 minutes (300s)** either direction.
* **Per-request nonce:** every request carries a unique UUID; a missing nonce is rejected outright (`connectmwp_missing_nonce`).
* **Signature replay cache:** each successful signature hash is stored as a transient (`cmwp_sig_<hash>`, ~360s TTL); a repeat is rejected.
* **Per-request static cache:** some hosts invoke `permission_callback` multiple times per request; the plugin caches its verdict in PHP memory so the second invocation doesn't falsely flag a replay.
* **Verification order:** HTTPS → key lookup → timestamp window → signature verify → replay check → capability check. The signature is verified **before** the replay check, so a bogus signature is rejected without touching the database.

### API token (B) verification

The token is verified by `verify_token_request`: HTTPS-only → token lookup by id → constant-time hash compare → per-IP rate limit → "bound user still exists / still has caps" guard → capability check. **No login session is created** — same thesis as the signature path.

### ChatGPT OAuth (C) verification

Standard OAuth 2.1: authorization-code + PKCE, short-lived access tokens (`cmwp_oat_`) with refresh rotation, verified on every `/mcp` call. The admin consent step is where the customer grants access; revoking in the "Your connections" table invalidates it.

### One-time pairing flow (stdio only)

1. Customer opens WP Admin → **Settings → connectMWP** → **Generate Pairing Code**.
2. WP renders a terminal command containing the site URL + a single-use 10-minute code, bound to the issuing admin user.
3. Customer pastes it into their terminal. The MCP client generates an Ed25519 keypair locally, uploads only the **public** key to `/wp-json/connectmwp/v1/enroll`, and stores the private key locally (mode `0600`).
4. The plugin validates the code, stores the public key against the issuing admin's account, returns a `key_id`. The customer's local config records `{ site, key_id, private_key_path, label }`.

**Support implications:** codes are one-shot and expire in 10 minutes; the private key never leaves the customer's machine (never ask them to send it); to reset, revoke in WP Admin → generate a new code → run `add-site --enroll` again.

### Capability scoping (least privilege — all methods)

No connection has inherent privileges. Each is **bound to a specific WordPress user**, and every operation is checked against that user's capabilities (`edit_posts`, `publish_posts`, `upload_files`, `manage_categories`, etc.) **without** `wp_set_current_user` — there's no login session, just per-operation checks.

* **Practical effect:** if a customer connected using a non-administrator account, the tools only succeed for operations that account could already perform manually. A subscriber can't create posts via connectMWP, just as they couldn't in WP Admin.

### Outbound fetch / SSRF protections (local MCP client, stdio path)

* **Host filtering:** when the AI uploads media by URL, the local client blocks fetches to loopback, link-local, RFC1918 private ranges, carrier-grade NAT (`100.64.0.0/10`), and other internal/reserved ranges — preventing SSRF against the customer's local network. (Hardened further in v2.3.8.)
* **File-type filter — SVG is REJECTED.** Uploaded media is restricted to raster image types: `.png`, `.jpg`/`.jpeg`, `.gif`, `.webp`, `.bmp`, `.tiff`. **SVG is deliberately refused** (since v2.3.8) because SVG is XML and a known cross-site-scripting carrier. If a customer asks why their SVG upload fails, this is expected — tell them to use PNG/JPG/WebP, or upload the SVG manually via WP Admin → Media if they trust it.
* **Size cap:** **10 MB** per file (enforced identically on client and plugin). For larger media, upload directly via WP Admin → Media.

---

## 5. Troubleshooting Support Guide (FAQ Matrix)

| Customer Issue | Root Cause | Actionable Solution for Agent |
| :--- | :--- | :--- |
| **"Pairing failed: enrollment code expired / invalid"** *(stdio)* | Code is single-use, 10-min TTL — waited too long, ran it twice, or typo. | WP Admin → **Settings → connectMWP → Generate Pairing Code** again, copy the new command, run it right away. *Reassure: a failed re-pair never destroys an existing working key.* |
| **"Signature verification failed" / 401 on every request** *(stdio)* | Usually clock skew (>±300s) between the customer's machine and the WP server. Less commonly: the key was revoked. | 1. Check the customer's system clock is set to update automatically (macOS: System Settings → General → Date & Time; Windows: Settings → Time & Language). <br>2. If clocks are fine, check WP Admin → Settings → connectMWP → "Your connections" — is their key still listed (not revoked)? If revoked, re-pair. <br>3. Still failing → ask the host to verify NTP sync on the server. |
| **"Pairing failed: HTTP 401/403"** when running `add-site --enroll` | Plugin inactive, OR a host firewall blocks `/wp-json/connectmwp/v1/enroll`. | 1. Confirm the connectMWP plugin is **Active** (WP Admin → Plugins). <br>2. Visit `https://<site>/wp-json/connectmwp/v1/enroll` in a browser — a working install returns a JSON error (e.g. 405); a blocked endpoint returns the host's 403/404 page. If blocked, whitelist `/wp-json/connectmwp/*` in the security plugin/WAF. |
| **API-token client (Antigravity/Gemini) gets 401** | Wrong/old token, token revoked, bound user lost capabilities, or the host strips `Authorization`. | 1. Re-generate the token (WP Admin → Settings → connectMWP → **API token** card) and re-paste — tokens are shown once and can't be recovered. <br>2. Confirm the bound WordPress user still exists and has the needed role. <br>3. If the host strips `Authorization`, enable the opt-in URL-path-token fallback in the same card (and advise rotating it, since URL tokens can appear in logs). |
| **ChatGPT "couldn't connect" / login loop / consent error** | Not signed in as an **administrator**, connector URL wrong, or consent not approved. | 1. The connector URL must be `https://<site>/wp-json/connectmwp/v1/mcp` with Authentication = **OAuth**. <br>2. On **Sign in**, they must log into **their own site** as an **Administrator** and click **Approve** on the consent screen. <br>3. To start fresh, revoke the OAuth connection in WP Admin → Settings → connectMWP → "Your connections", then re-add the connector in ChatGPT. |
| **"REST API Blocked"** (401/403/404 from content tools, not enroll) *(stdio)* | Security suites/WAFs (Sucuri, Cloudflare, Wordfence) block WP REST routes. | **connectMWP auto-falls back to Admin-AJAX** (`/wp-admin/admin-ajax.php`) with the same signature headers — usually no action needed. If both fail, whitelist `/wp-json/connectmwp/*` and `/wp-admin/admin-ajax.php`. |
| **"Command not found: npx / node"** *(stdio)* | Node.js not installed / not on PATH. | Install Node.js 18+ from [nodejs.org](https://nodejs.org) (macOS: `brew install node`). Verify with `node --version` (≥ v18). *Note: only the stdio clients need Node — ChatGPT and API-token clients need no local install.* |
| **"Claude can't find tools" / MCP server not loading** *(stdio)* | Registration failed or the IDE needs a restart. | 1. Confirm registration: `claude mcp add connectmwp -- npx -y connectmwp-mcp` (the `--` matters). <br>2. `claude mcp list` should show `connectmwp` connected. <br>3. Fully quit Claude (⌘Q, not just close) and relaunch. <br>4. Still failing → check Claude's MCP log for `npm error 404` or `Server disconnected` and share with the dev team. |
| **"Permission denied" / capability errors** *(any method)* | The bound WordPress user lacks capabilities for the operation. | connectMWP acts with the **exact capabilities of the bound user**. Confirm that user is Administrator or Editor with the right caps. Re-connect from an account with appropriate privileges if needed. |
| **"Upload failed — file too large or wrong type"** | File > 10 MB, or an SVG (now rejected), or a non-image type. | The 10 MB cap and **raster-image-only** rule (no SVG, since v2.3.8) are deliberate safety limits. For larger media or SVG, upload directly via WP Admin → Media. *Media upload is also unavailable to ChatGPT and API-token clients — only the stdio clients can upload.* |
| **"Cached response showing stale data"** (rare) | A managed host's edge cache (LiteSpeed on SiteGround/NameHero) is caching signed responses. | Ensure the plugin is current, then purge the cache: WP Admin → LiteSpeed Cache → Toolbox → Purge All. (Resolved in-plugin since v2.0.12; cached entries can otherwise persist up to 7 days.) |

---

## 6. Escalation & Diagnostic Information

If you can't resolve the issue, escalate to engineering with:

1. **Connection method** — stdio pairing (Claude/Cursor/Cline), API token (Antigravity/Gemini), or ChatGPT OAuth. This determines almost everything else.

2. **Software versions:**
   * Plugin: WP Admin → Plugins → connectMWP → version next to the name.
   * MCP client *(stdio only)*: `npx -y connectmwp-mcp --version`, or check the installed `package.json` version.
   * Node *(stdio only)*: `node --version`.

3. **Site environment:** WordPress version (Dashboard → At a Glance), hosting provider, active security plugins, and whether LiteSpeed/WP Rocket/other caching is active.

4. **Exact error message** as it appeared in: the terminal (CLI errors), the AI client's MCP log (Claude on macOS: `~/Library/Logs/Claude/mcp.log`), or the browser dev-tools Network tab (WP Admin issues / ChatGPT OAuth).

5. **Reproduction steps** — what they ran, expected, and actually got.

**What NOT to ask the customer for:** their private key file contents (`~/.connectmwp/<host>.ed25519`), their WordPress admin password, an API token over an insecure channel, or screenshots of a live pairing code (treat these as secrets).

For confirmed bugs or feature gaps, escalation goes to the project's GitHub issues at <https://github.com/stefanhz/connectMWP/issues> with the diagnostics above attached.
