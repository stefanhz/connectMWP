# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

connectMWP (connectmwp.com) is a **decentralized bridge** that lets local AI clients (Claude Desktop/Code, Cursor) publish to self-hosted WordPress sites over MCP. The defining architectural constraint: **no central server sits in the daily traffic path.** The AI client talks straight to the user's WordPress site over HTTPS. A central web app exists only to run the one-time OAuth handshake. This is a deliberate decision (security honeypot avoidance, $0 proxy cost, no uptime liability) — see `_internal/concept.md` §5 for the dismissed alternatives, and do not reintroduce a request-proxying server.

## Three components, three independent versions

This repo is a monorepo of three loosely-coupled deliverables. Each has its **own** version number — when bumping versions, change the one that actually changed:

| Dir | What | Lang | Version source |
|-----|------|------|----------------|
| `connectmwp-agent/` | WordPress plugin (the gatekeeper that runs on the user's site) | PHP, single file | `Version:` header in `connectmwp-agent.php` |
| `connectmwp-mcp/` | Local MCP client (stdio server the AI client spawns) | Node ESM | `version` in `package.json` |
| `connectmwp-server/` | Central web app (OAuth handshake UI only) | Next.js 16 / React 19 | `version` in `package.json` |

The README's setup commands and version references can drift from the plugin header — trust the source files over the README.

## Commands

```bash
# Central server (connectmwp-server/)
cd connectmwp-server
npm run dev      # next dev
npm run build    # next build
npm run lint     # eslint

# MCP client (connectmwp-mcp/) — run directly, no build step
node connectmwp-mcp/index.js add-site --site "https://example.com" --token "connectmwp_tk_..." [--default]
node connectmwp-mcp/index.js list-sites
node connectmwp-mcp/index.js remove-site --site "https://example.com"
node connectmwp-mcp/index.js set-default --site "https://example.com"
# With no CLI arg it boots as an MCP stdio server (how the AI client invokes it).

# WordPress plugin — no build. Packaging is manual:
#   zip the connectmwp-agent/ folder into connectmwp-agent.zip for upload via WP admin.
#   (connectmwp-agent.zip is gitignored.)
```

There is no automated test suite in any component.

## How the pieces talk

**Daily runtime path** (`connectmwp-mcp/index.js` → `connectmwp-agent.php`):
- Client calls `{site}/wp-json/connectmwp/v1/{posts|media|tags|categories}` with auth in a **custom header `X-ConnectMWP-Auth: Bearer <token>`**, NOT the standard `Authorization` header. This is the whole reason the product works: managed hosts (SiteGround, Kinsta) strip `Authorization` at the edge proxy. Never move auth to a standard header.
- Every request also carries `X-ConnectMWP-Timestamp` + `X-ConnectMWP-Nonce` for replay protection (plugin enforces a 300s clock-skew window and stores used nonces for ~6 min).
- **Admin-AJAX fallback:** if REST returns 401/403/404 or the fetch throws, the client retries the same operation through `wp-admin/admin-ajax.php` (action `connectmwp_api`, sub-action in `connectmwp_action`). The plugin exposes every capability via *both* REST and AJAX because some hosts lock down REST entirely. **Any new tool must be wired into both paths** — the REST route + handler in the plugin, the AJAX action mapping in `callWordPressAjax()`, and the AJAX dispatch in the plugin's `handle_ajax_request()`.

**Auth model (plugin side):** authentication hooks `determine_current_user` (priority 5). A valid token resolves to the WP user who approved it; the remote caller then acts **with exactly that user's capabilities** — there is no separate permission layer, so capability checks (`check_edit_permission` etc.) are real WP cap checks. Tokens are stored only as SHA-256 hashes in user meta `_connectmwp_tokens`; the raw `connectmwp_tk_...` token is shown once and never persisted server-side.

**One-time OAuth handshake** (`connectmwp-server` ↔ plugin):
1. `connectmwp-server` home page redirects the user's browser to `{site}/wp-admin/admin.php?page=connectmwp-auth&callback=...&state=...`.
2. The plugin renders its own standalone approval screen (`render_clean_oauth_screen` — deliberately bypasses `wp_iframe` to avoid third-party plugin markup conflicts) and, on approve, mints a token and redirects back to `/callback`.
3. `connectmwp-server/src/app/callback/page.tsx` reads `token` + `site` from the URL **in the browser** and renders the `claude mcp add` command / JSON config. The token is never sent to the connectmwp.com server — preserve this property in any callback changes.

## Component-specific gotchas

- **`connectmwp-server` uses Next.js 16** (see its `AGENTS.md`): APIs and conventions differ from older Next.js in your training data. Consult `node_modules/next/dist/docs/` or Context7 before writing Next.js code here. App Router, React 19, Tailwind v4. UI is currently inline-styled (no component library).
- **`connectmwp-mcp` config** lives at `~/.connectmwp.json`: `{ defaultSite, sites: { <normalizedUrl>: { token, label, updated } } }`. URLs are normalized (https:// prefix added, trailing slash stripped) and matched by hostname so protocol/slash differences still resolve. Each tool takes an optional `site` arg; absent it, `defaultSite` is used. `CONNECTMWP_SITE`/`CONNECTMWP_TOKEN` env vars are a legacy fallback.
- **`_internal/`** (gitignored) holds `concept.md` (full spec & rationale), `diagnose.py`, and `connectmwp-auth-bridge.php` — reference material, not shipped code.
