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
