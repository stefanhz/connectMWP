## What is connectMWP?

connectMWP is a decentralized Model Context Protocol (MCP) server that links local AI tools (such as Claude Desktop, Cursor, and Claude Code) directly to your self-hosted WordPress site's API, enabling automated content publishing workflows. The project is completely open source; you can find the source repository on [GitHub](https://github.com/stefanhz/connectMWP) (opens in new window).

## Is the connection secure?

Yes. All requests and credentials bypass our servers entirely. The local MCP client communicates directly with your WordPress installation over HTTPS using custom authentication headers and cryptographic signatures. 

Furthermore, **website owners have full, absolute control** at any point:
- Access tokens are generated locally on your own WordPress site.
- Tokens are stored in your WordPress database using secure one-way SHA-256 hashing. The raw token is displayed to you once and is never stored on the server.
- You can revoke or delete any active connection token at any time from your WordPress settings page (**Settings -> connectMWP**), which immediately blocks all future access from that client.

## Do I need to run a local server (like localhost)?

No. The MCP server runs via standard input/output (stdio) directly inside your AI client (e.g., Claude). It does not listen on local network ports, preventing firewall issues or antivirus blocks.

## How does it handle edge caching and hosting WAFs?

Standard WordPress API calls get blocked or cached by reverse proxies and web application firewalls (like SiteGround Security, Sucuri, Kinsta). connectMWP uses an early-hooked custom auth header and dynamic cache-busting queries to bypass these blocks cleanly.

## Can I manage multiple WordPress sites?

Yes! connectMWP supports multi-site configurations. You register the background server process once, and add multiple domains via the 'add-site' CLI helper. You can target specific sites using the optional 'site' parameter.

## How much does connectMWP cost?

connectMWP is **100% free and open source**. There are no monthly subscriptions, no usage tiers, and no central API proxy costs. Since your AI client communicates directly with your own WordPress server, you never pay middleware fees.
