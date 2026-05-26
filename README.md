# wpConnect — Architecture & Integration Plan

This project aims to connect AI services with multiple WordPress websites to automate research, topic generation, content drafting, image generation, and remote publishing.

## 1. Diagnosing & Overcoming WordPress Application Password Blockers

If you tried to set up Automattic's WordPress MCP connection and it failed, the root cause is almost certainly one of the following:

### A. Authorization Header Stripping (Most Common)
Many web hosting configurations (e.g., Apache with CGI/FastCGI, Nginx reverse proxies, or GoDaddy/SiteGround configurations) strip the HTTP `Authorization` header by default before passing it to PHP. Since WordPress Application Passwords rely on Basic Authentication (`Authorization: Basic [base64_credentials]`), WordPress receives the request, sees no authorization headers, and rejects it with a `401 Unauthorized` or `403 Forbidden` error.

**How to fix it:**
*   **For Apache (`.htaccess`):** Add the following lines to the top of your `.htaccess` file:
    ```apache
    <IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
    </IfModule>
    ```
*   **For Nginx:** Ensure your `fastcgi_params` block passes the Authorization header:
    ```nginx
    fastcgi_param HTTP_AUTHORIZATION $http_authorization;
    ```

### B. Security Plugins
Security plugins like Wordfence, Sucuri, iThemes/Solid Security, and WP Cerberus are designed to protect WordPress from brute-force attacks and unsolicited REST API access.
*   **Wordfence / Sucuri:** Often blocks REST API requests originating from unknown external IPs or requests that contain basic authentication headers.
*   **WP Cerberus / SiteGround Security:** Have toggles to completely disable the WordPress REST API for unauthenticated users, or disable Application Passwords entirely.

### C. Web Application Firewalls (WAF) & Host Blocks
Managed WordPress hosts (WP Engine, Kinsta, SiteGround) or Cloudflare WAFs block `POST` requests to standard REST API endpoints (like `/wp-json/wp/v2/posts`) when they originate from automated scripts, cloud hosting IPs (Vercel, AWS), or headers without typical browser User-Agents.

---

## 2. A Better, More Secure Connection Approach

Relying on standard Application Passwords over `Authorization: Basic` is fragile because it is heavily targeted by hackers and therefore highly blocked by security infrastructure. 

For an open-source project or custom system, a **much better and more secure** approach is a **Custom WordPress Agent Plugin** combined with **Cryptographic Signing (Ed25519)**. This is actually the method already implemented in your `wpmgmt_app` agent:

1.  **Custom REST Endpoint / Admin-AJAX Fallback**:
    *   Instead of hitting standard endpoints like `/wp-json/wp/v2/posts`, register a custom endpoint: `/wp-json/wpconnect/v1/publish`.
    *   For environments where REST is completely blocked, use a custom **Admin-AJAX fallback** (e.g. `/wp-admin/admin-ajax.php?action=wpconnect_publish`). WAFs and security plugins rarely block Admin-AJAX because it is essential for frontend themes and plugins.
2.  **Ed25519 Cryptographic Signatures (No Shared Passwords)**:
    *   The agent plugin on WordPress stores the **Public Key** of the controller (your AI application).
    *   The AI application keeps the **Private Key** secure in its environment variables.
    *   Every request sent to WordPress includes a timestamp and is signed with the private key (sent in custom headers like `X-WPConnect-Signature` and `X-WPConnect-Timestamp`).
    *   WordPress verifies the signature using PHP's native `libsodium` (via `sodium_crypto_sign_verify_detached`).
    *   **Security Invariant:** Even if someone intercepts your request, they cannot replay it (due to timestamp/replay logs), and even if the WordPress database is compromised, the attacker only gets the *public key*, meaning they cannot generate valid signed commands to compromise other sites.
    *   **Custom Headers:** Custom headers like `X-WPConnect-Signature` are rarely stripped by Nginx/Apache, unlike the default `Authorization` header.

---

## 3. MCP Server vs. Standalone App (What's the take?)

### Option A: Pure MCP Server
*   **How it works:** A local server running on your computer that exposes WordPress database/REST API actions as tools directly into your AI client (Antigravity/Claude Desktop).
*   **Pros:** Fits neatly inside your chat. You can say: *"Suggest a topic and post it to my site"* and the AI runs the tools directly in real-time.
*   **Cons:** **Highly unsuitable for fully automated workflows.** MCP servers are stateless, run locally, and rely on the AI client being open with active user prompts. They cannot run background cron jobs, manage database states of competitor research over weeks, run queues, or execute automated workflows overnight.

### Option B: Standalone Web App (Next.js + DB)
*   **How it works:** A server-side application (like your `wpmgmt_app`) that has a dashboard, database (Supabase), and background workers (cron).
*   **Pros:** 
    *   **Background Jobs:** Can run automated tasks (e.g., scrape competitors daily, run LLM pipelines to generate ideas).
    *   **Queuing / States:** Stores suggested topics in a queue for your review.
    *   **Human-in-the-Loop:** A premium dashboard where you review suggested topics, edit the AI-generated drafts, inspect generated images, and click "Approve & Publish".
    *   **Multi-Site Management:** Easily manages multiple sites, API credentials, and scheduling tables.
*   **Cons:** Not directly accessible as a tool inside your code editor's chat client.

### Option C: The Hybrid Approach (Recommended)
Build a **Standalone Dashboard Web App** (Next.js + DB) as the orchestrator, and expose an **MCP Interface** from it.
*   The Next.js app handles the heavy lifting: database, background research, content queues, and image hosting.
*   The app exposes a secure REST API for its functions.
*   We create a lightweight **MCP Server** that connects to your Next.js orchestrator. When you are chatting with Antigravity, you can run tools like `wpconnect_get_ideas` or `wpconnect_publish_draft` which trigger the background pipelines in your Next.js app.

---

## 4. Proposed Development Path

1.  **wpConnect Agent Plugin**: A lightweight, standalone WordPress plugin that registers secure custom REST and Admin-AJAX routes, authenticating requests via API keys or cryptographic signatures.
2.  **Next.js Orchestrator (or extending `wpmgmt_app`)**:
    *   Since you already have `wpmgmt_app` which uses a Custom Agent (`wpmgmt-agent.php`) and has a Supabase backend with Ed25519 verification, we can evaluate if we should build on top of that architecture or create a clean, dedicated Next.js/Supabase project in `/Users/stefanhz/Documents/aiSpace/wpConnect`.
3.  **Research & Content Pipelines**: Integrate Gemini/Claude API for research, topic suggestions, and copywriting, and Imagen/DALL-E for image generation.
