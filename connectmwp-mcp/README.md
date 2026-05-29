# connectmwp-mcp

> **Verified against:** connectMWP **v2.0.18** (lockstep across plugin, MCP client, central server).
> **Last reviewed:** 2026-05-28.
> **Re-verify when:** the `add-site` / `remove-site` / `set-default` / `list-sites` flag surface changes, or the security-model summary below diverges from `_internal/ARCHITECTURE.md`.

Local MCP (Model Context Protocol) client for [connectMWP](https://github.com/stefanhz/connectMWP) — connects AI clients (Claude Desktop, Claude Code, Cursor) directly to self-hosted WordPress sites over HTTPS, with no central proxy in the daily traffic path.

Pairs with the **connectMWP WordPress plugin**, which authenticates each request via per-request **Ed25519 detached signatures** (no login sessions, no `Authorization` header — compatible with managed hosts and WAF/2FA security plugins like Wordfence, Solid Security, miniOrange, LiteSpeed).

## Install

```bash
# As a Claude Desktop / Claude Code MCP server (recommended):
claude mcp add connectmwp -- npx -y connectmwp-mcp

# Or run directly:
npx -y connectmwp-mcp
```

## Pair a WordPress site

1. Install the connectMWP plugin on your WordPress site (download from the [main repo](https://github.com/stefanhz/connectMWP)).
2. In **WP Admin → Settings → connectMWP**, click **Generate Pairing Code**.
3. Run the command shown on the WP screen, e.g.:

```bash
npx -y connectmwp-mcp add-site --enroll "https://yourblog.com,pairing_code_here"
```

This generates a local Ed25519 keypair, uploads only the public key to your site, and stores the private key in `~/.connectmwp/<hostname>.ed25519`. Site list lives in `~/.connectmwp.json`.

## CLI

```bash
npx -y connectmwp-mcp list-sites
npx -y connectmwp-mcp set-default --site "https://example.com"
npx -y connectmwp-mcp remove-site --site "https://example.com"
```

With no CLI arg, it boots as an MCP stdio server (how AI clients invoke it).

## Tools exposed to the AI client

`connectmwp_get_posts`, `connectmwp_get_post`, `connectmwp_create_post`, `connectmwp_update_post`, `connectmwp_delete_post`, `connectmwp_upload_media`, `connectmwp_list_tags`, `connectmwp_create_tag`, `connectmwp_list_categories`, `connectmwp_create_category`.

Each accepts an optional `site` argument; otherwise the default site (set via `set-default`) is used.

## Security model

- **No central server in the daily path.** The MCP client talks straight to your WordPress site.
- **Session-less Ed25519 signatures.** Every request carries an Ed25519 signature over `{method, path, timestamp, nonce, body-hash}`. The WordPress plugin verifies in `permission_callback` without calling `wp_set_current_user`, so 2FA/security plugins don't see a login event to revoke.
- **Replay protection.** 300s clock-skew window + per-request nonce stored ~6 minutes.
- **Private key never leaves your machine.** Stored at `~/.connectmwp/<hostname>.ed25519` with 0600 perms.

## Requirements

- Node.js ≥ 18
- A WordPress site running the [connectMWP plugin](https://github.com/stefanhz/connectMWP) (v2.0.10+)

## License

GPL-2.0
