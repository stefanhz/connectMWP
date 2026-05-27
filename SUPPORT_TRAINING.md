# wpConnect Support Training & Troubleshooting Manual

This document provides customer support agents with the technical background, security context, and troubleshooting steps needed to resolve customer inquiries. 

---

## 1. Core Architecture & Philosophy

wpConnect is a **decentralized, serverless bridge** between a user's local AI editor (e.g. Claude Desktop, Cursor, Claude Code) and their self-hosted WordPress site. 

### Key Concept: The Daily Traffic Path is Local
Unlike typical integration services (e.g. Zapier), **no central server sits in the traffic path for daily publishing operations**. 
* **Local MCP Server:** The AI client spawns a local Model Context Protocol (MCP) server process on the user's computer via standard input/output (stdio).
* **Direct Communication:** The local server sends HTTPS requests directly to the user's self-hosted WordPress API.
* **Handshake Site Only:** The central website (`connectmwp.com`) is a stateless setup assistant. It is used **only** during the initial one-time OAuth handshake to simplify token exchange.

```
[ Local AI Client ] <---> [ Local MCP Server ]
                                 |
                        (Direct HTTPS Calls)
                                 |
                                 v
                     [ User's WordPress Site ]
```

### Support Insight: Security Shield
If a customer asks about data privacy or server uptime:
* **Zero-Knowledge:** We do not collect or store their WordPress credentials, website database, posts, or API tokens. 
* **Compromise Immunity:** Even if `connectmwp.com` goes offline or is compromised, their publishing pipelines are unaffected. The active token hashes live only in their local config file (`~/.wpconnect.json`) and their own WordPress database.

---

## 2. The Multi-Site System

wpConnect supports managing multiple WordPress sites from a single AI session.

### Configuration Storage
All site records are saved in the user's home directory:
* **File Location:** `~/.wpconnect.json` on macOS/Linux.
* **Structure:** Contains a list of site domains, their active tokens, and a reference to the `defaultSite`.

### Support Scenarios & Fixes
* **How the AI knows which site to edit:** The user can pass an optional `site` parameter (e.g., `wpconnect_create_post(site: "blog.com", ...)`). If omitted, the tool defaults to the site configured as `defaultSite`.
* **Managing Sites via CLI:** Support can guide users to run these local terminal commands:
  * **List linked sites:** `npx -y wpconnect-mcp list-sites`
  * **Add/Link a new site:** `npx -y wpconnect-mcp add-site --site "https://blog.com" --token "wpconnect_tk_..."`
  * **Change default site:** `npx -y wpconnect-mcp set-default --site "https://blog.com"`
  * **Remove a site:** `npx -y wpconnect-mcp remove-site --site "https://blog.com"`

---

## 3. Security Mechanism (Safe for Support Staff)

wpConnect implements robust defense systems. When customers experience authentication issues, they are often triggering these protection layers.

### Early custom authentication headers
Instead of standard HTTP `Authorization` headers, wpConnect uses `X-WPConnect-Auth: Bearer <token>`. 
* **Why?** Popular hosting edge routers (e.g., Kinsta, SiteGround, WP Engine) strip incoming `Authorization` headers by default before they hit PHP. A custom header bypasses this restriction cleanly.

### Replay Attack Protection
Every single command sent by the local MCP client includes two validation headers:
1. `X-WPConnect-Timestamp` (POSIX epoch time)
2. `X-WPConnect-Nonce` (Unique random string)

The WordPress plugin verifies these on every incoming request:
* **Clock Skew Window:** The timestamp must match the WordPress server's clock within **5 minutes (300 seconds)**. 
* **Atomic Nonce Storage:** Each nonce is checked and saved as an individual atomic option (`wpc_nonce_[hash]`) in the database. If a nonce was already registered, it is rejected immediately, preventing replay attacks and race conditions. A pruning query runs synchronously on every valid authenticated request to immediately clear expired nonces and keep database option table bloat at zero.
* **Token Verification First:** The plugin checks if the token is valid in user metadata *before* executing the nonce check, preventing unauthenticated database-write floods (DoS protection).

### Safe Redirection & Fragment Token Delivery (Implicit Flow)
* **Allowed Host Check:** Redirection during the connection handshake is restricted to authorized domains only (`connectmwp.com` and `connect-mwp.vercel.app`). Other targets are blocked automatically.
* **Fragment-Based Token Exchange:** Tokens are delivered back to the setup site inside the URL hash fragment (`#token=...`) instead of the query parameters (`?token=...`). Since fragments are kept entirely in the browser and never sent over the HTTP request line, the client's token never leaks into Vercel or proxy access logs.

### Outbound Fetch and SSRF Protections
* **Host Filtering:** The local MCP client blocks outbound file/image downloads attempting to access loopback (`127.0.0.1`, `::1`), link-local (`169.254.0.0/16`), or RFC1918 private ranges, preventing Server-Side Request Forgery.
* **File Upload Filters:** Local media uploads are restricted to approved image file extensions (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg`, `.bmp`, `.tiff`) and capped to a maximum size of 10MB to protect memory resources.

---

## 4. Troubleshooting Support Guide (FAQ Matrix)

| Customer Issue | Root Cause | Actionable Solution for Agent |
| :--- | :--- | :--- |
| **"Authentication Failed" / Invalid Token** | The token entered does not match the hashed version stored on WordPress. | Ask the user to log into WordPress, navigate to **Settings -> wpConnect**, revoke the old connection name, generate a new token, and execute the site-linking CLI command again. *Remind them the token is shown only once.* |
| **"Invalid Timestamp / Nonce expired"** | The user's local computer clock or the WordPress hosting server clock is drift-desynchronized. | 1. Ask the user to check their system clock settings and ensure "Set time automatically" is enabled.<br>2. If their local clock is correct, the hosting provider's server time is drift-delayed. Ask the host to sync NTP. |
| **"REST API Blocked" (401/403/404)** | Hosting security suites or WAFs (Sucuri, Cloudflare, Wordfence) are blocking WordPress REST routes. | **wpConnect automatically falls back to Admin-AJAX.** Ensure the user has not disabled admin-ajax entirely. No user actions are usually required since the local server retries operations through `/wp-admin/admin-ajax.php` automatically. |
| **"Command not found: npx / node"** | Node.js is not installed or not in the user's shell path. | Ask them to install Node.js (v18+) from [nodejs.org](https://nodejs.org). |
| **"Claude cannot find tools"** | The MCP server registration failed or the IDE needs a restart. | 1. Ask the user to restart Claude Desktop or Cursor completely.<br>2. Verify the registration command was run: `claude mcp add wpconnect npx -y wpconnect-mcp` (or with absolute path for local testing). |
| **"Permission Denied" (User Role)** | The WordPress user account used to link wpConnect doesn't have sufficient privileges. | wpConnect acts with the exact capabilities of the WordPress user who generated the token. Confirm the user's role is **Administrator** or **Editor** with post editing/upload capabilities. |

---

## 5. Escalate & Diagnostic Script

If a support agent cannot resolve the issue, they can ask the user to run the diagnostic tool.
1. Download or locate `_internal/diagnose.py` in their package.
2. Run `python3 diagnose.py` in the terminal.
3. This will perform automated ping tests, check SSL certificates, query header persistence, test rest-routes vs ajax-routes, and print a clean diagnostic report to copy-paste for development engineers.
