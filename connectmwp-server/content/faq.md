## What is connectMWP?

connectMWP is a decentralized Model Context Protocol (MCP) bridge that links your AI clients — such as Claude Desktop, Claude Code, Cursor, Cline, ChatGPT, and Gemini/Antigravity — directly to your self-hosted WordPress site, enabling automated content publishing workflows. The project is completely open source; you can find the source repository on [GitHub]({{REPO_URL}}) (opens in new window).

## Which AI clients are supported, and how does each connect?

connectMWP supports three connection methods, and the plugin's **Settings → connectMWP** page walks you through whichever one your client needs:

1. **Claude Desktop, Claude Code, Cursor, Cline** (and other stdio MCP clients) — pair once using a small local client and a cryptographic **device key**. This is the most secure path (every request is individually signed; see below).
2. **ChatGPT** — connect remotely by adding connectMWP as a connector and signing in with **OAuth**. No local install required.
3. **Antigravity, Gemini CLI, and other remote MCP clients** — connect remotely using a **per-site API token** that you generate (and can revoke) in your WordPress settings.

You can connect as many clients as you like, and revoke any of them at any time.

## Is the connection secure?

Yes. All requests and credentials bypass our servers entirely — the connection runs straight from your AI client to your own WordPress site over HTTPS.

For device-key clients (Claude, Cursor, Cline), connectMWP uses strong cryptography:
- Pairing is completed locally using a single-use enrollment code generated inside your WordPress settings page (**Settings → connectMWP**).
- The local client generates an Ed25519 cryptographic keypair at pairing time and uploads only the **public key** to your site.
- The **private key never leaves your local machine**, and no secret keys or passwords are stored in your WordPress database.
- Every API call is verified using a detached cryptographic signature, which helps prevent token interception or theft.

Remote clients that can't run the local signer (ChatGPT, Gemini, Antigravity) instead use a revocable, per-site OAuth connection or API token. Whichever method you use, **you have full, absolute control** — revoke or delete any connected client from your WordPress settings page, and all future access stops immediately.

## Do I need to run a local server (like localhost)?

No. For desktop clients, the MCP server runs via standard input/output (stdio) directly inside your AI client (e.g. Claude) — it does not listen on local network ports, which avoids firewall and antivirus issues. Remote clients (ChatGPT, Gemini, Antigravity) need nothing installed locally at all; they connect straight to your site.

## How does it handle edge caching, 2FA, and hosting WAFs?

Standard WordPress API calls and logins are often policed or blocked by WAFs, 2FA requirements, and edge proxies (like SiteGround Security, Sucuri, Kinsta, or Cloudflare). connectMWP avoids these problems by operating **session-less** — it never logs in a user session or uses cookies, and instead authorizes each request directly (by cryptographic signature, OAuth token, or API token). Because there is no login session, 2FA prompts never intercept the connection, and the integration keeps working alongside your security plugins instead of being blocked by them.

## Can I manage multiple WordPress sites?

Yes! connectMWP supports multi-site configurations. For desktop clients you register the local client once and add multiple domains via the `add-site` CLI helper, then target a specific site using the optional `site` parameter. Each site is paired independently, so a key or token for one site never grants access to another.

## How much does connectMWP cost?

connectMWP is **100% free and open source**. There are no monthly subscriptions, no usage tiers, and no central API proxy costs. Since your AI client communicates directly with your own WordPress server, you never pay middleware fees — you just use your existing AI subscription (such as Claude Pro/Team or ChatGPT).

## What are the system requirements and prerequisites?

**On the WordPress side (always required):**

- PHP version 7.2 or higher.
- The PHP **libsodium** extension enabled (most modern hosts enable this by default for core WordPress security features).
- An active SSL certificate (HTTPS is strictly enforced for safety).

**On your computer (only for desktop / stdio clients — Claude Desktop, Claude Code, Cursor, Cline):**

- **Node.js (v18 or higher)** — the local client runs via the `npx` package runner.
- An MCP-compatible desktop client: **Claude Desktop** (macOS/Windows), **Cursor IDE**, or **VS Code** with an MCP extension such as Cline or Roo Code.

**ChatGPT, Gemini CLI, and Antigravity** connect to your site remotely and need **no local install** — you add connectMWP as a connector (ChatGPT signs in with OAuth; Gemini/Antigravity use a per-site API token).

*Note: You do not need to install Next.js or build this website locally. Next.js only powers this public guide; the local client runs purely on lightweight, native Node.js.*

## How do I check if Node.js is installed and get it set up?

Open your computer's terminal (Terminal on macOS, or Command Prompt/PowerShell on Windows) and run:
```bash
node -v
npm -v
```
If these commands print version numbers (e.g., `v18.x.x` or higher), you are ready.

If they print "command not found" or similar errors:
1. Download the **LTS (Long Term Support)** version of Node.js from the official [Node.js Website](https://nodejs.org/) and run the installer.
2. Restart your terminal window and run the commands again to verify the installation.

## Why was connectMWP created instead of using existing solutions?

connectMWP was built to address two limitations common to other WordPress MCP servers and AI integrations:

1. **Compatibility with WordPress security & 2FA plugins.** Most alternatives — including Automattic's official WordPress MCP adapter — authenticate using **Application Passwords** (or OAuth), which are tied to a WordPress login identity. On production sites running security plugins (such as Wordfence, WP 2FA, or Solid Security), those credentials are frequently blocked at the REST API by 2FA enforcement and firewall rules — so the integration simply fails to connect. connectMWP instead uses **session-less, signature-based authentication** (Ed25519 detached signatures) to authorize individual API requests, so it works *alongside* your security plugins rather than being blocked by them — without asking you to weaken your site's security.
2. **No extra middleware or proxy fees.** Some integration tools route every request through a centralized third-party server, which can see your content and credentials and adds a subscription cost. connectMWP connects your AI client **directly** to your site — there are no middleware servers in the request path and nothing extra to buy, so you simply use your existing AI subscription at **$0 middleware cost**.
