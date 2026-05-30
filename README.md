# connectMWP

**Current Release Version: v2.0.33**
*(Doc verified against v2.0.33 on 2026-05-30.)*

connectMWP is a secure, decentralized Model Context Protocol (MCP) server that connects local AI clients (such as Claude Desktop, Cursor, and Claude Code) directly to self-hosted WordPress websites to draft content, upload media, and manage posts directly from your workspace.

The architecture is **100% decentralized and session-less**. AI requests are authenticated on a per-request basis using Ed25519 detached signatures over HTTPS, bypassing any central servers and carrying $0 proxy costs. This makes it completely immune to WAF blocks and WordPress login security/2FA plugin restrictions.

Each signed request carries a per-request UUID nonce as the second field of the Ed25519 canonical (`timestamp · nonce · method · path · sha256(sorted_query) · sha256(body)`), so two functionally-identical requests produce different signatures and a captured request cannot be replayed against the site within the ±300s clock-skew window. The plugin layers an atomic signature-hash cache on top as defense-in-depth.

## Why connectMWP? (Motivation & Design Choices)

connectMWP started with a problem I couldn't solve on my own site. There are good WordPress + MCP options out there already — Automattic's official WordPress MCP server chief among them — and I tried them first. I just couldn't get one working against my own setup: the security plugins I run kept blocking the connection, and I wasn't willing to weaken my site's defenses to get past them. So I built an approach that works *with* a hardened site instead of around it.

Two design choices fell out of that:

1. **Works alongside your security plugins, not against them.** Most integrations authenticate by logging in as a WordPress user on each call. On a locked-down site that login is exactly what your security plugins and firewall are there to scrutinize — 2FA challenges, cookie policies, and tools like Wordfence, Solid Security, or miniOrange can stop it cold. connectMWP is **100% session-less**: it verifies a per-request Ed25519 signature in the permission callback and never establishes a login session at all. There's no login for the security layer to challenge, so a hardened site and connectMWP can coexist — no compromises on either side.
2. **A direct connection, with nothing in the middle.** connectMWP is **fully decentralized** — the local MCP client signs the request and talks straight to your site over HTTPS. Nothing is routed through a third-party proxy, so there are no extra API keys, no middleware subscription, and no central server in the traffic path ($0 proxy cost). It works with the AI subscription you already pay for.

I'm sharing this publicly because experience has taught me that when I hit a wall like this, I'm rarely the only one. If you ran into the same problem, I hope it saves you the detour. The goal here is simple: things that *work*.

---

## 1. Quick Start

**Most users:** follow **Section 4 (Public Release Setup)** below — `connectmwp-mcp` is now on the public npm registry, so the AI client can be installed with `npx -y connectmwp-mcp`.

The remainder of this section documents the **source-checkout flow** used when developing against a local clone of the repo. 

### Step 1: Install & Activate the WordPress Plugin
1. Download the latest WordPress plugin zip from `connectmwp-agent.zip` (found in the root of this repo, or downloaded from the settings page of an active installation).
2. Log into your WordPress site's admin dashboard (e.g. `https://2morrow.ai`).
3. Go to **Plugins -> Add New -> Upload Plugin**, upload the ZIP, and click **Activate**.
4. Go to **Settings -> connectMWP** in your WP sidebar.

### Step 2: Register the Server in Claude (Run Once Globally)
In your terminal, register the absolute path of your local MCP client script:
```bash
claude mcp add connectmwp node /Users/stefanhz/Documents/aiSpace/connectMWP/connectmwp-mcp/index.js
```
*(To make the server available globally across all folders on your Mac, add the `--scope user` flag: `claude mcp add --scope user connectmwp node ...`)*

### Step 3: Pair Your WordPress Sites (Run per Site)
1. In the WordPress settings screen (**Settings -> connectMWP**), click **Generate Pairing Code**.
2. Copy the generated pairing terminal command and execute it in your terminal. For local files, run:
```bash
node /Users/stefanhz/Documents/aiSpace/connectMWP/connectmwp-mcp/index.js add-site --enroll "https://yourblog.com,pairing_code"
```
During this flow, your local client generates a secure Ed25519 keypair and uploads only the public key to your site. The private key remains secure on your machine (`~/.connectmwp/<hostname>.ed25519`), and the site details are stored in `~/.connectmwp.json`.

---

## 2. Using the MCP Tools

Once setup is complete, the AI client will automatically discover the following tools in the background. You can target specific sites using the optional `site` parameter.

### List of Tools
*   `connectmwp_get_posts` — Retrieves titles, date, URLs, and IDs of existing posts.
*   `connectmwp_get_post` — Retrieves full details of a single post by ID (to analyze link opportunities).
*   `connectmwp_create_post` — Creates a new post draft or publishes it immediately.
*   `connectmwp_update_post` — Updates an existing post (essential for injecting internal SEO links).
*   `connectmwp_upload_media` — Uploads featured or inline images/graphs to your media library.
*   `connectmwp_delete_post` — Trashes or permanently deletes a post by ID.
*   `connectmwp_list_tags` — Lists all active tags on the site.
*   `connectmwp_list_categories` — Lists all active categories on the site.
*   `connectmwp_create_category` — Creates a new category on the site.
*   `connectmwp_create_tag` — Creates a new tag on the site.

### Prompt Examples
*   **Query Default Site:** *"Show me the latest 5 posts using connectMWP."*
*   **Query Specific Site:** *"List the active categories on myblog.com using connectMWP."*
*   **Cross-site Workflow:** *"Read the tags list on 2morrow.ai, write an article draft on 2morrow.ai, and assign 3 of those tags to it."*

---

## 3. IDE Configurations

### Cursor IDE Setup
Add the following JSON block to your Cursor MCP settings (Settings -> Features -> MCP):
```json
{
  "mcpServers": {
    "connectmwp": {
      "command": "node",
      "args": [
        "/Users/stefanhz/Documents/aiSpace/connectMWP/connectmwp-mcp/index.js"
      ]
    }
  }
}
```
*Note: After adding the config in Cursor, you must run the **Step 3 (Pair Site)** terminal command once to link each website's credentials.*

### Claude Desktop Setup
If you prefer configuring Claude Desktop manually, add the following to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "connectmwp": {
      "command": "node",
      "args": [
        "/Users/stefanhz/Documents/aiSpace/connectMWP/connectmwp-mcp/index.js"
      ]
    }
  }
}
```

---

## 4. Public Release Setup

Once `connectmwp-mcp` is published to the public npm registry, the commands will simplify for regular users:

1. **Register Server (Once):**
   ```bash
   claude mcp add connectmwp npx -y connectmwp-mcp
   ```
2. **Pair Site (Per Site):**
   ```bash
   npx -y connectmwp-mcp add-site --enroll "https://domain.com,pairing_code"
   ```
