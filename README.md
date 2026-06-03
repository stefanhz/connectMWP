# connectMWP

> **Verified against:** connectMWP **v2.2.0** (all three components, lockstep).
> **Last reviewed:** 2026-06-02.
> **Re-verify when:** the client connection model changes (new auth types, new client categories), the pairing CLI surface changes, the ChatGPT OAuth flow changes, or the `/mcp` endpoint URL or connector URL format changes.

connectMWP is a secure, decentralized Model Context Protocol (MCP) server that connects AI clients directly to self-hosted WordPress sites — letting you draft content, upload media, and manage posts from your AI workspace.

The architecture is **100% decentralized**. Requests go straight from the AI client to your WordPress site over HTTPS; no central server sits in the path ($0 proxy cost, no uptime liability). Authentication is per-request — no WordPress login session is ever created, so 2FA plugins and security firewalls have nothing to intercept.

---

## Connecting your AI client

Different clients connect in different ways. Use the method that matches your client.

| Client | Connection method | Setup summary |
|---|---|---|
| Claude Desktop, Claude Code, Cursor, Cline | **Stdio + Ed25519 pairing** | Register `npx -y connectmwp-mcp` once, then pair each site with a one-time code from WP Admin |
| Antigravity, Gemini CLI, other remote MCP clients that support a custom auth header | **API token (Bearer header)** | Generate a token in WP Admin, paste it as `Authorization: Bearer <token>` in the client alongside the connector URL |
| ChatGPT | **OAuth** | Add a connector in ChatGPT with the `/mcp` URL and choose OAuth; sign in as an administrator when prompted; no token is generated or pasted |

### Method 1 — Claude / Cursor / Cline (local stdio)

These clients spawn the `connectmwp-mcp` stdio server locally and use Ed25519 signatures on every request. Setup is two steps: register the server once, then pair each site once.

**Register the server in your AI client (once per machine):**

For Claude Desktop or Claude Code:
```bash
claude mcp add connectmwp npx -y connectmwp-mcp
```

For Cursor (Settings → Features → MCP) or other clients, add:
```json
{
  "mcpServers": {
    "connectmwp": {
      "command": "npx",
      "args": ["-y", "connectmwp-mcp"]
    }
  }
}
```

**Pair a WordPress site (once per site):**

1. In your WordPress admin, go to **Settings → connectMWP**.
2. Click **Generate Pairing Code**. A one-shot terminal command appears, valid for 10 minutes.
3. Run that command in your terminal:
   ```bash
   npx -y connectmwp-mcp add-site --enroll "https://yoursite.com,cmwp_enroll_<code>"
   ```

On success, a fresh Ed25519 keypair is generated locally. Only the public key is sent to your site; the private key stays on your machine at `~/.connectmwp/<hostname>.ed25519`.

**Multiple sites:** each site gets its own pairing. All paired sites are stored in `~/.connectmwp.json`. Pass an optional `site` argument to any tool to target a specific site; otherwise the default site is used.

### Method 2 — Antigravity, Gemini CLI & other header-capable remote clients

Clients that support a custom `Authorization` header authenticate with a per-site API token.

1. In WP Admin → **Settings → connectMWP**, find the **API token** card.
2. Choose the WordPress user the client will act as, optionally add a label, and click **Generate token**.
3. Copy the token (`cmwp_cgpt_<hex>`) — it is shown once and cannot be recovered; if lost, revoke and generate a new one.
4. In your client, add a remote MCP server with:
   - **URL:** `https://yoursite.com/wp-json/connectmwp/v1/mcp`
   - **Authentication:** Bearer token — paste the token you copied

**Multiple sites:** add one server entry per site and give each a distinct name (for example, `connectmwp-myblog`) so tools do not get mixed up across sites.

**If your host strips the `Authorization` header:** enable the URL-embedded token fallback in the WP Admin card (opt-in, off by default). This embeds the token in the URL path instead of a header. Note that URL-embedded tokens can appear in server and CDN access logs — rotate the token periodically if you use this option.

### Method 3 — ChatGPT (OAuth)

ChatGPT's connector UI offers only OAuth, No-Auth, and Mixed authentication — there is no API-key field. ConnectMWP's plugin acts as its own OAuth 2.1 Authorization Server directly on your site, so no central server is involved.

1. In ChatGPT, open **Settings → Apps (Connectors)**, enable Developer mode, and create a new connector.
2. Set the connector URL to `https://yoursite.com/wp-json/connectmwp/v1/mcp`.
3. Set Authentication to **OAuth**.
4. Click **Sign in**. You will be sent to your site's login screen — sign in as an **administrator**.
5. On the consent screen, review the access and click **Approve**.

The connection appears in WP Admin → **Settings → connectMWP → Connected apps (OAuth)**. To disconnect ChatGPT, click Revoke there.

**Multiple sites:** add one connector per site in ChatGPT.

---

## 1. Quick Start (source checkout)

The section above covers end-user setup from the published npm package. This section documents the **source-checkout flow** used when developing against a local clone of the repo.

### Step 1: Install & Activate the WordPress Plugin
1. Download the latest plugin zip from `connectmwp-server/public/connectmwp.zip` (or build locally — see CLAUDE.md Commands).
2. In your WordPress admin, go to **Plugins → Add New → Upload Plugin**, upload the zip, and click **Activate**.
3. Go to **Settings → connectMWP**.

### Step 2: Register the Server in Claude (Run Once Globally)
In your terminal:
```bash
claude mcp add connectmwp node /path/to/connectMWP/connectmwp-mcp/index.js
```
*(Add `--scope user` to make it available across all folders.)*

### Step 3: Pair Your WordPress Sites (Run per Site)
1. In WP Admin → **Settings → connectMWP**, click **Generate Pairing Code**.
2. Copy and run the generated command:
```bash
node /path/to/connectMWP/connectmwp-mcp/index.js add-site --enroll "https://yoursite.com,pairing_code"
```

---

## 2. Using the MCP Tools

Once set up, your AI client discovers the following tools automatically. Use the optional `site` parameter to target a specific site.

| Tool | Purpose |
|---|---|
| `connectmwp_get_posts` | List post titles, dates, URLs, and IDs |
| `connectmwp_get_post` | Get full details of a single post by ID |
| `connectmwp_create_post` | Create a new draft or publish immediately |
| `connectmwp_update_post` | Update an existing post |
| `connectmwp_upload_media` | Upload images or files to the media library |
| `connectmwp_delete_post` | Trash or permanently delete a post |
| `connectmwp_list_tags` | List all tags on the site |
| `connectmwp_list_categories` | List all categories on the site |
| `connectmwp_create_category` | Create a new category |
| `connectmwp_create_tag` | Create a new tag |

Note: `connectmwp_upload_media` is only available to stdio clients (Claude, Cursor, Cline). ChatGPT cannot upload media over the remote MCP endpoint.

### Prompt Examples
- *"Show me the latest 5 posts using connectMWP."*
- *"List the active categories on my site using connectMWP."*
- *"Read the tags, write a draft article, and assign three tags to it."*

---

## 3. IDE Configurations (source checkout)

### Cursor IDE Setup
Add to Cursor MCP settings (Settings → Features → MCP):
```json
{
  "mcpServers": {
    "connectmwp": {
      "command": "node",
      "args": ["/path/to/connectMWP/connectmwp-mcp/index.js"]
    }
  }
}
```

### Claude Desktop Setup
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "connectmwp": {
      "command": "node",
      "args": ["/path/to/connectMWP/connectmwp-mcp/index.js"]
    }
  }
}
```

---

## 4. Public Release Setup

`connectmwp-mcp` is published on the public npm registry. End users install it with:

1. **Register the server (once):**
   ```bash
   claude mcp add connectmwp npx -y connectmwp-mcp
   ```
2. **Pair a site (per site):**
   ```bash
   npx -y connectmwp-mcp add-site --enroll "https://yoursite.com,pairing_code"
   ```
