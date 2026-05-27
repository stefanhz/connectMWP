# wpConnect (connectmwp.com)

**Current Release Version: v1.2.2**

wpConnect is a secure, decentralized bridge that connects local AI clients (such as Claude Desktop, Cursor, and Claude Code) directly to self-hosted WordPress websites to automate research, topic generation, content drafting, image uploading, and remote publishing.

The architecture is **100% decentralized for daily operations**. All AI requests are executed directly from your local machine to your WordPress site over HTTPS, bypassing any central servers and carrying $0 proxy costs.

---

## 1. Quick Start (Local Development Setup)

Because the npm package `wpconnect-mcp` is not yet published to the public registry, you must point your configurations to your local files. 

### Step 1: Install & Activate the WordPress Plugin
1. Locate the packaged plugin file: [wpconnect-agent.zip](./wpconnect-agent.zip)
2. Log into your WordPress site's admin dashboard (e.g. `https://2morrow.ai`).
3. Go to **Plugins -> Add New -> Upload Plugin**, upload the ZIP, and click **Activate**.
4. Go to **Settings -> wpConnect** in your WP sidebar.

### Step 2: Register the Server in Claude (Run Once Globally)
In your terminal, register the absolute path of your local MCP client script:
```bash
claude mcp add wpconnect node /Users/stefanhz/Documents/aiSpace/wpConnect/wpconnect-mcp/index.js
```
*(To make the server available globally across all folders on your Mac, add the `--scope user` flag: `claude mcp add --scope user wpconnect node ...`)*

### Step 3: Link Your WordPress Sites (Run per Site)
From the WordPress settings screen (**Settings -> wpConnect**), generate a connection token. Copy the linking command and execute it in your terminal:
```bash
node /Users/stefanhz/Documents/aiSpace/wpConnect/wpconnect-mcp/index.js add-site --site "https://2morrow.ai" --token "wpconnect_tk_your_token"
```
This saves the credentials securely into your local config file (`~/.wpconnect.json`). 

---

## 2. Using the MCP Tools

Once setup is complete, the AI client will automatically discover the following tools in the background. You can target specific sites using the optional `site` parameter.

### List of Tools
*   `wpconnect_get_posts` — Retrieves titles, contents, URLs, and IDs of existing posts.
*   `wpconnect_create_post` — Creates a new post draft or publishes it immediately.
*   `wpconnect_update_post` — Updates an existing post (essential for injecting internal SEO links).
*   `wpconnect_upload_media` — Uploads featured or inline images/graphs to your media library.
*   `wpconnect_list_tags` — Lists all active tags on the site.
*   `wpconnect_list_categories` — Lists all active categories on the site.

### Prompt Examples
*   **Query Default Site:** *"Show me the latest 5 posts using wpConnect."*
*   **Query Specific Site:** *"List the active categories on myblog.com using wpConnect."*
*   **Cross-site Workflow:** *"Read the tags list on 2morrow.ai, write an article draft on 2morrow.ai, and assign 3 of those tags to it."*

---

## 3. IDE Configurations

### Cursor IDE Setup
Add the following JSON block to your Cursor MCP settings (Settings -> Features -> MCP):
```json
{
  "mcpServers": {
    "wpconnect": {
      "command": "node",
      "args": [
        "/Users/stefanhz/Documents/aiSpace/wpConnect/wpconnect-mcp/index.js"
      ]
    }
  }
}
```
*Note: After adding the config in Cursor, you must run the **Step 3 (Link Site)** terminal command once to link each website's credentials.*

### Claude Desktop Setup
If you prefer configuring Claude Desktop manually, add the following to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "wpconnect": {
      "command": "node",
      "args": [
        "/Users/stefanhz/Documents/aiSpace/wpConnect/wpconnect-mcp/index.js"
      ]
    }
  }
}
```

---

## 4. Public Release Setup (SaaS Flow)

Once `wpconnect-mcp` is published to the public npm registry, the commands will simplify for regular users:

1. **Register Server (Once):**
   ```bash
   claude mcp add wpconnect npx -y wpconnect-mcp
   ```
2. **Link Site (Per Site):**
   ```bash
   npx -y wpconnect-mcp add-site --site "https://domain.com" --token "wpconnect_tk_..."
   ```
3. **Central Handshake:** Users can optionally go to `https://connectmwp.com` (deployed in `/connectmwp-server`) to complete the oauth connection flow automatically.
