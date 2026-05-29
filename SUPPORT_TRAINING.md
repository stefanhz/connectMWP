# connectMWP Support Training & Troubleshooting Manual

> **Verified against:** connectMWP **v2.0.23** (all three components, lockstep).
> **Last reviewed:** 2026-05-28.
> **Re-verify when:** the pairing flow, signature headers, capability scoping, REST/AJAX fallback behavior, or any user-visible error message changes.
>
> **v2.0.15-v2.0.16 UX changes worth knowing for support:** after a successful pairing, the customer's terminal prints a friendly multi-line summary (`✓ Connected to "<site>" / ✓ Acting as: <user> — <role> / ✓ Can: <capabilities>`) confirming identity + capabilities. The plugin's settings page shows a green "Connection Status" banner with paired-client count, a "What now?" panel for ~1 hour after the most-recent pairing (with test prompt + multi-AI-client note), and highlights the newest row in the Paired Clients table. As of v2.0.16, the page also auto-updates without manual refresh: while a pairing code is visible, JS polls every 3s, and on successful pairing the card flips to "🎉 Pairing successful!" and the page reloads automatically. If a customer says "is it connected?" you can ask them to revisit Settings → connectMWP — the banner answers it.

This document gives customer support agents (and any AI support bot trained on this material) the technical background, security context, and troubleshooting steps needed to resolve customer inquiries. It describes the **v2 architecture** — session-less Ed25519 signature authentication. Any reference you see in older notes to "tokens", `connectmwp_tk_...`, or a browser-based OAuth handshake is from the obsolete v1 design and should be ignored.

---

## 1. Core Architecture & Philosophy

connectMWP is a **decentralized, serverless bridge** between a user's local AI editor (e.g. Claude Desktop, Claude Code, Cursor) and their self-hosted WordPress site.

### Key Concept: The Daily Traffic Path is Local

Unlike typical integration services (e.g. Zapier), **no central server sits in the traffic path for daily publishing operations**.

* **Local MCP Server:** The AI client spawns a local Model Context Protocol (MCP) server process on the user's computer (`connectmwp-mcp`, installed via `npx -y connectmwp-mcp`) and communicates with it over standard input/output (stdio).
* **Direct Communication:** That local server signs each request with the user's own Ed25519 private key and sends it directly to the WordPress REST API over HTTPS.
* **Central Site Out of the Daily Path:** `connectmwp.com` exists only as marketing/onboarding and to host the downloadable plugin zip. Once a customer is paired, the central site is **never contacted** during normal publishing operations.

```
[ Local AI Client ] <---> [ Local MCP Server (signer) ]
                                 |
                        (Direct HTTPS, Ed25519-signed)
                                 |
                                 v
                     [ User's WordPress Site ]
                     (verifies signature, no login session)
```

### Support Insight: Security Shield

If a customer asks about data privacy or server uptime:

* **Zero-Knowledge:** We do not collect, store, or ever see the customer's WordPress credentials, website database, posts, or private signing key. The private key is generated on the customer's machine during pairing and never leaves it.
* **Compromise Immunity:** Even if `connectmwp.com` goes offline or is compromised, customer publishing pipelines are unaffected. The site config (`~/.connectmwp.json`) and the private key file (`~/.connectmwp/<hostname>.ed25519`) live on the customer's machine; the customer's WordPress database stores only the **public** key — useless to an attacker for forging requests.
* **2FA / Security-Plugin Friendly:** connectMWP authenticates each request via a cryptographic signature checked in the plugin's `permission_callback`. It **never creates a WordPress login session**, so security plugins like Wordfence, Solid Security, miniOrange, and WP 2FA have nothing to intercept or revoke — by design.

---

## 2. The Multi-Site System

connectMWP supports managing multiple WordPress sites from a single AI session.

### Configuration Storage

All site records are saved in the customer's home directory:

* **JSON config:** `~/.connectmwp.json` on macOS/Linux (Windows equivalent: `%USERPROFILE%\.connectmwp.json`). Stores a list of site URLs, the associated `key_id`, the path to the private key, an optional label, and a `defaultSite` reference.
* **Private keys:** `~/.connectmwp/<hostname>.ed25519` per paired site, mode `0600`. These files are sensitive — treat them like SSH private keys; do **not** ask customers to share their contents in support tickets.

### Support Scenarios & Fixes

* **How the AI knows which site to edit:** Tools accept an optional `site` parameter (e.g., `connectmwp_create_post(site: "blog.com", ...)`). If omitted, the tool defaults to the site configured as `defaultSite` in `~/.connectmwp.json`.

* **Managing Sites via CLI:** Support can walk customers through these local terminal commands:

  | Action | Command |
  |---|---|
  | List linked sites | `npx -y connectmwp-mcp list-sites` |
  | Add/Update a site (pair) | `npx -y connectmwp-mcp add-site --enroll "<site_url>,<pairing_code>" [--default] [--label "<friendly name>"]` |
  | Change default site | `npx -y connectmwp-mcp set-default --site "https://blog.com"` |
  | Remove a site from config | `npx -y connectmwp-mcp remove-site --site "https://blog.com"` |

* **Adding a site requires a pairing code** generated in WP Admin → **Settings → connectMWP → Generate Pairing Code**. Codes are single-use and expire after 10 minutes. The same `add-site --enroll` command is used to (a) connect a new site and (b) re-connect a site whose key was revoked — there is no separate "update" command. Re-pairing safely overwrites the existing local key and config entry (via a temp-file + rename pattern, so a failed re-pair never destroys a working key).

* **Removing a site** via `remove-site` only deletes the local JSON entry; it does **not** revoke the key on the WP side and does **not** delete the local private key file. To fully decommission a pairing, the customer should also revoke the key in WP Admin → Settings → connectMWP → Paired Clients.

---

## 3. Security Mechanism (Safe for Support Staff)

connectMWP implements robust defense layers. When customers experience authentication issues, they are often triggering one of these protections.

### Custom Authentication Headers (Edge-Proxy Survival)

Every signed request carries three custom HTTP headers:

| Header | Purpose |
|---|---|
| `X-ConnectMWP-Key` | The `key_id` of the paired client making the request |
| `X-ConnectMWP-Timestamp` | Unix epoch seconds (must be within ±300s of the WP server clock) |
| `X-ConnectMWP-Signature` | Base64-encoded Ed25519 detached signature over the canonical request |
| `X-ConnectMWP-Body-Hash` *(uploads only)* | SHA-256 of the multipart file payload — added in v2.0.10, prevents upload tampering |

**Why custom headers?** Popular managed hosts (Kinsta, SiteGround, WP Engine, etc.) and many WAFs strip the standard `Authorization` header at the edge before it reaches PHP. Custom headers bypass that restriction cleanly.

### Replay Attack Protection

The WordPress plugin checks every incoming request for replay attempts:

* **Clock Skew Window:** The timestamp must match the WordPress server's clock within **5 minutes (300 seconds)** in either direction.
* **Signature Replay Cache:** Each successful request's signature hash (`sha256(signature)`) is stored as a transient option (`cmwp_sig_<hash>`) with a ~360-second TTL. If the same signature comes in twice, the second one is rejected.
* **Per-Request Static Cache:** Some hosts invoke `permission_callback` multiple times in a single HTTP request (security-plugin filters + REST dispatch quirks). The plugin caches the verification verdict in PHP memory so the second invocation reuses the result instead of falsely flagging a replay.
* **Verification Order:** HTTPS → key lookup → timestamp window → signature verify → replay check → capability check. The signature is verified **before** the replay check, so a request with a bogus signature is rejected without ever touching the database options.

### One-Time Pairing Flow

Pairing is **entirely local** — no browser redirects, no central token exchange:

1. Customer opens WP Admin → **Settings → connectMWP** → clicks **Generate Pairing Code**.
2. WP renders a terminal command containing the site URL + a single-use 10-minute pairing code, bound to the WordPress admin user who issued it.
3. Customer pastes the command into their terminal. The MCP client generates an Ed25519 keypair on their machine, uploads only the **public** key to `/wp-json/connectmwp/v1/enroll`, and stores the private key locally (mode `0600`).
4. The plugin validates the pairing code, stores the public key against the issuing admin's user account, and returns a `key_id`. The customer's local config records `{ site, key_id, private_key_path, label }`.

**Support implications:**

* Pairing codes are **one-shot** — if the customer ran it once successfully, the same code cannot be used again. They must generate a new code in WP Admin if they want to re-pair.
* Pairing codes **expire after 10 minutes** — if a customer waits too long between generating and running, they'll see `Pairing failed: enrollment code expired` or similar.
* The private key **never leaves the customer's machine**. Support should never ask customers to send the contents of their `~/.connectmwp/<host>.ed25519` file. If they need to reset the pairing for any reason, the path is: revoke key in WP Admin → generate new pairing code → run `add-site --enroll` again.

### Capability Scoping (Least Privilege)

The MCP server has **no inherent privileges** — each paired key is bound to a specific WordPress user account, and every operation is checked against that user's WordPress capabilities (`edit_posts`, `publish_posts`, `upload_files`, `manage_categories`, etc.). The plugin does this WITHOUT calling `wp_set_current_user` — there's no login session, just per-operation capability checks against the bound user ID.

* **Practical effect for support:** if a customer paired connectMWP using a non-administrator account, the tools will only succeed for operations that account can already perform manually in WP Admin. A subscriber-level account cannot create posts via connectMWP, just as they couldn't create posts by clicking around in WP Admin.

### Outbound Fetch and SSRF Protections (Local MCP Client)

* **Host Filtering:** When the AI uploads media by URL, the local MCP client blocks fetches to loopback (`127.0.0.1`, `::1`), link-local (`169.254.0.0/16`), and RFC1918 private IP ranges. This prevents Server-Side Request Forgery against the customer's local network.
* **File Upload Filters:** Uploaded media is restricted to approved image extensions (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg`, `.bmp`, `.tiff`) and capped at **10 MB** per file to protect memory resources.

---

## 4. Troubleshooting Support Guide (FAQ Matrix)

| Customer Issue | Root Cause | Actionable Solution for Agent |
| :--- | :--- | :--- |
| **"Pairing failed: enrollment code expired" / "invalid enrollment code"** | The pairing code is single-use, 10-min TTL. They waited too long, ran it twice, or typo. | Ask them to log into WP Admin → **Settings → connectMWP** → click **Generate Pairing Code** again, copy the new command, and run it right away. *Reassure them that any working key for this site is still safe — the v2.0.11 safety fix ensures a failed re-pair never destroys an existing pairing.* |
| **"Signature verification failed" / 401 on every request** | Most commonly: clock skew between the customer's machine and the WordPress server (>±300s). Less commonly: the key was revoked on the WP side. | 1. Ask the customer to check their system clock: macOS **System Settings → General → Date & Time → Set time and date automatically** = ON; Windows **Settings → Time & Language** = automatic. <br>2. If clocks are correct, check WP Admin → Settings → connectMWP → Paired Clients — is the row for their key_id still present and not revoked? If revoked, re-pair (see row 1). <br>3. If still failing, ask the host to verify NTP sync on the WP server. |
| **"Pairing failed: HTTP 401" or 403** when running `add-site --enroll` | The plugin isn't active on the WP site, OR a host firewall is blocking the `/wp-json/connectmwp/v1/enroll` endpoint. | 1. Confirm the connectMWP plugin is installed and **Active** in WP Admin → Plugins. <br>2. Visit `https://<their-site>/wp-json/connectmwp/v1/enroll` in a browser — a working install returns a JSON `405` or similar; a blocked endpoint returns the host's 403/404 page. If blocked, the customer needs to whitelist `/wp-json/connectmwp/*` in their security plugin or WAF. |
| **"REST API Blocked"** (401/403/404 from regular content tools, not enroll) | Hosting security suites or WAFs (Sucuri, Cloudflare, Wordfence) are blocking WordPress REST routes. | **connectMWP automatically falls back to Admin-AJAX** — the local MCP client retries the same operation via `/wp-admin/admin-ajax.php` with the same signature headers. Usually no action required. If both REST and AJAX fail, the customer needs to whitelist `/wp-json/connectmwp/*` and `/wp-admin/admin-ajax.php` in their security plugin. |
| **"Command not found: npx / node"** | Node.js is not installed or not in the customer's shell PATH. | Ask them to install Node.js 18+ from [nodejs.org](https://nodejs.org). On macOS, `brew install node` also works. Verify with `node --version` (should be `v18.x` or higher). |
| **"Claude cannot find tools" / MCP server not loading** | The MCP server registration failed or the IDE needs a restart. | 1. Confirm registration was run: `claude mcp add connectmwp -- npx -y connectmwp-mcp` (the `--` is important). <br>2. Verify the registration: `claude mcp list` should show `connectmwp` with status `connected`. <br>3. Fully quit Claude Desktop (⌘Q on macOS — not just close window) and relaunch. <br>4. If still failing, check Claude Desktop's MCP log file for `npm error 404` (the npm package failed to resolve) or `Server disconnected` — share the log lines with the dev team. |
| **"Permission Denied" or capability errors** | The WordPress user account whose admin paired connectMWP doesn't have sufficient capabilities for the requested operation. | connectMWP acts with the **exact capabilities of the WordPress user who initiated the pairing**. Confirm that user has role **Administrator** or **Editor**, with the right caps for the operation. Re-pair from an account with appropriate privileges if needed. |
| **"Upload failed" — file too large or wrong type** | The customer is trying to upload a file >10 MB or a non-image extension. | The 10 MB cap and image-only extensions are deliberate safety limits. For larger media, the customer must upload directly via WP Admin → Media. |
| **"Cached response showing stale data"** (very rare; was a CRITICAL bug fix in v2.0.12) | Their managed host's edge cache (LiteSpeed common on SiteGround / NameHero) is caching signed responses. | They need to update to v2.0.12 or newer (current is v2.0.18). After updating, they should also **purge the LiteSpeed cache** in WP Admin → LiteSpeed Cache → Toolbox → Purge All; cached entries can persist up to 7 days otherwise. |

---

## 5. Escalation & Diagnostic Information

If a support agent cannot resolve the issue, escalate to engineering with the following information collected from the customer:

1. **Software versions:**
   * Plugin: WP Admin → Plugins → connectMWP → version shown next to the plugin name.
   * MCP client: `npx -y connectmwp-mcp --version` (if supported) OR `cat ~/.npm/_npx/*/node_modules/connectmwp-mcp/package.json | grep version`.
   * Node: `node --version`.

2. **Site environment:**
   * WordPress version (Dashboard → At a Glance).
   * Hosting provider (SiteGround / Kinsta / Cloudways / VPS / etc.).
   * Active security plugins (Wordfence, Solid Security, miniOrange, etc.).
   * Whether LiteSpeed Cache, WP Rocket, or similar caching is active.

3. **Exact error message** as it appeared in:
   * The customer's terminal (for CLI errors).
   * Claude Desktop's MCP log (`~/Library/Logs/Claude/mcp.log` on macOS, equivalent path on Windows).
   * The browser's developer-tools Network tab if the issue is in WP Admin.

4. **Reproduction steps** — what they ran, what they expected, what actually happened.

**What NOT to ask the customer for:** their private key file contents (`~/.connectmwp/<host>.ed25519`), their WordPress admin password, or screenshots of their pairing code (codes are single-use anyway, but treat them as secrets while live).

For confirmed bugs or feature gaps, escalation goes to the project's GitHub issues at <https://github.com/stefanhz/connectMWP/issues> with the diagnostic info above attached.
