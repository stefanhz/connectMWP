## What is connectMWP?

connectMWP is a decentralized Model Context Protocol (MCP) server that links local AI tools (such as Claude Desktop, Cursor, and Claude Code) directly to your self-hosted WordPress site's API, enabling automated content publishing workflows. The project is completely open source; you can find the source repository on [GitHub](https://github.com/stefanhz/connectMWP) (opens in new window).

## Is the connection secure?

Yes. All requests and credentials bypass our servers entirely. The local MCP client communicates directly with your WordPress installation over HTTPS using custom authentication headers and cryptographic signatures. 

Furthermore, **website owners have full, absolute control** at any point:
- Pairing is completed locally using a single-use enrollment code generated inside your WordPress settings page (**Settings -> connectMWP**).
- The local MCP client generates a secure Ed25519 cryptographic keypair at pairing time and uploads only the **public key** to your site.
- The **private key** never leaves your local machine, and no secret keys or passwords are stored in your WordPress database.
- Every API call is verified using detached cryptographic signatures, preventing token interception or theft.
- You can revoke or delete any paired client key at any time from your WordPress settings page, which immediately blocks all future access.

## Do I need to run a local server (like localhost)?

No. The MCP server runs via standard input/output (stdio) directly inside your AI client (e.g., Claude). It does not listen on local network ports, preventing firewall issues or antivirus blocks.

## How does it handle edge caching and hosting WAFs?

Standard WordPress API calls and sessions are often policed or blocked by WAFs, 2FA requirements, and edge proxies (like SiteGround Security, Sucuri, Kinsta, Cloudflare). connectMWP bypasses these issues by operating **session-less** (never logging in a user session or using cookies) and verifying request signatures directly. This prevents 2FA prompts from intercepting API calls and ensures compatibility with strict hosting policies.

## Can I manage multiple WordPress sites?

Yes! connectMWP supports multi-site configurations. You register the background server process once, and add multiple domains via the 'add-site' CLI helper. You can target specific sites using the optional 'site' parameter.

## How much does connectMWP cost?

connectMWP is **100% free and open source**. There are no monthly subscriptions, no usage tiers, and no central API proxy costs. Since your AI client communicates directly with your own WordPress server, you never pay middleware fees.

## What are the system requirements and prerequisites?

To run the connectMWP local client and connect it to your WordPress site, you need the following:

1. **Node.js (v18 or higher)**: The local MCP client is written in Node.js and run using the `npx` package runner. You must have Node.js installed on your computer.
2. **An MCP-compatible AI client**: 
   - **Claude Desktop** (macOS or Windows)
   - **Cursor IDE**
   - **VS Code** (with MCP plugins like Cline or Roo Code)
3. **WordPress Site Requirements**: 
   - PHP version 7.2 or higher.
   - The PHP **libsodium** extension enabled (most modern hosts enable this by default for core WordPress security features).
   - An active SSL certificate (HTTPS is strictly enforced for safety).

*Note: You do not need to install Next.js or build the Next.js website locally. Next.js is only used to run this public guide website; the local client runs purely on lightweight, native Node.js.*

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

connectMWP was built to address two primary limitations found in other WordPress MCP servers and integrations:

1. **Compatibility with WordPress Security & 2FA Plugins**: Popular alternatives (including Automattic's official WordPress MCP server) require creating active WordPress user sessions. On production sites running security plugins (such as Wordfence, WP 2FA, Solid Security), these sessions are discarded or blocked due to 2FA enforcement. connectMWP uses **session-less, signature-based authentication** (Ed25519 detached signatures) to authorize individual API requests directly, bypassing session policies and security plugin restrictions without requiring you to reduce your website's security.
2. **No Extra API Keys or Middleware Fees**: Many other integration tools route requests through a centralized third-party proxy, requiring separate API registration and adding middleware subscription fees. connectMWP connects your local AI client (e.g., Claude) **directly** to your website. There are no middleware servers in the request path and no extra API keys to buy—allowing you to use your existing subscription plans (like Claude Pro/Team) for $0 middleware cost.
