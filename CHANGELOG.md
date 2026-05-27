# Changelog

All notable changes to connectMWP are recorded here. Each of the three
components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) carries
its own version; entries note which component changed.

## 2026-05-27 — v2.0.9

### Added
- **connectmwp-agent — delete post handler.** Added support for trashing/deleting posts via REST `DELETE` on `/posts/<id>` route.
- **connectmwp-agent — added featured_media, categories, tags to get_post.** Updated `get_post_handler` to return taxonomy lists and the featured media ID by default.
- **connectmwp-mcp — delete post tool.** Registered the new `connectmwp_delete_post` tool and implemented the REST `DELETE` execution pathway (including AJAX fallback routing).
- **connectmwp-mcp — trash status.** Supported the `'trash'` status in the create/update post tool validation enum schemas.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.9`.

## 2026-05-27 — v2.0.8

### Added
- **connectmwp-agent — exposed Last Used column.** Added back the "Last Used" date column in the WordPress admin "Paired Clients" listing table.

### Changed
- **connectmwp-agent — styled Revoke Access button.** Made the "Revoke Access" action button in the "Paired Clients" listing more compact (smaller padding, font-size, and height) to save horizontal layout space.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.8`.

## 2026-05-27 — v2.0.7

### Added
- **README.md — design motivation section.** Added a new "Why connectMWP?" section explaining the advantages of connectMWP (session-less request signatures bypassing security/2FA plugins, direct decentralized calls with $0 middleware proxy costs).
- **connectmwp-server — design motivation FAQ.** Expanded the FAQ page on the website with a dedicated entry answering why connectMWP was built instead of other market solutions.

### Changed
- **README.md — updated pairing delimiters.** Replaced pipe character (`|`) delimiters with shell-safe commas (`,`) in all CLI pairing instructions to prevent terminal command redirect errors.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.7`.

## 2026-05-27 — v2.0.6

### Fixed
- **connectmwp-agent — supported standard link and url fields in post retrieval.** Modified `get_posts_handler` and `get_post_handler` to return the post permalink for both `link` and `url` field requests. This ensures compatibility with AI clients requesting standard REST `link` fields for internal-linking workflow tasks.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.6`.

## 2026-05-27 — v2.0.5

### Fixed
- **connectmwp-agent — layout fix for settings configuration snippets.** Replaced the layout-breaking inline-block block/width styles with standard inline syntax highlight spans (bold blue for the `connectmwp` server block, soft faded grey for surrounding boilerplate). This resolves the alignment issue on closing brackets and eliminates horizontal scrollbar clipping inside the `<pre>` tag.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.5`.

## 2026-05-27 — v2.0.4

### Added
- **connectmwp-agent — dynamic countdown timer.** Added a JavaScript countdown timer in the "Action Required: Go Pair Your Local Environment Now" panel, showing exactly how long (minutes/seconds) remains until the single-use pairing code expires.
- **connectmwp-agent — step-by-step pairing instructions.** Added clear preparation steps in the settings page to guide the user on opening their terminal, checking their local Node.js environment, copying/running the command, and refreshing the settings page to see the client show up in "Paired Clients".

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.4`.

## 2026-05-27 — v2.0.3

### Changed
- **connectmwp-agent — visually highlighted configuration snippets.** Redesigned the Cursor and Claude Desktop JSON config codeblocks inside the settings page to fade out standard `mcpServers` boilerplate and draw focus directly to the `connectmwp` server block.
- **connectmwp-agent — added integration merge tips.** Added a helpful notice above configuration pre-blocks to guide users on merging the server definition block if they have existing MCP servers configured.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.3`.

## 2026-05-27 — v2.0.2

### Changed
- **connectmwp-server — updated onboarding guide copy.** Replaced the obsolete pipe character (`|`) with a shell-safe comma (`,`) in the terminal command copy-block on the homepage to avoid command-line redirections.

### Added
- **connectmwp-server — system requirements and prerequisites FAQ.** Added new sections detailing the requirements (Node.js version, PHP libsodium extension, HTTPS SSL requirement) and instructions on verifying local Node/npm environments.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.2`.

## 2026-05-27 — v2.0.1

### Fixed
- **connectmwp-agent — settings page pairing code display state loss.** Fixed a bug where the generated one-time pairing code was not displayed if the options page was reloaded or redirected. The active unexpired code is now fetched directly from WordPress options on every settings page load until it expires (10 minutes) or is successfully consumed.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.1`.

## 2026-05-27 — v2.0.0

### Added
- **Signature-Based Session-less Authentication:** Rebuilt the entire authentication layer using Ed25519 asymmetric cryptography. The client signs every outgoing request using its private key, and the WordPress plugin verifies request signatures using PHP's native `sodium_crypto_sign_verify_detached` on custom headers (`X-ConnectMWP-Key`, `X-ConnectMWP-Timestamp`, `X-ConnectMWP-Signature`).
- **WAF and 2FA Bypass:** Eliminated WordPress user session creation (`wp_set_current_user` and `determine_current_user` hooks), allowing requests to pass cleanly through 2FA/login-security plugins and WAFs.
- **Local Enrollment Command:** Added `add-site --enroll` command to `connectmwp-mcp` CLI to initiate secure pairing via a short-lived dashboard-generated pairing code.
- **New tools:** Registered `connectmwp_get_post`, `connectmwp_create_category`, and `connectmwp_create_tag` as MCP tools, making the functional API fully aligned with the content creation pipeline.

### Changed
- **Next.js Homepage Redesign:** Replaced the obsolete URL redirect input and OAuth callback flow on `connectmwp.com` with a static step-by-step setup and local pairing instructions portal.

### Fixed
- **Dynamic Plugin Version:** Resolved badge drift by referencing the new class version constant dynamically in the dashboard settings page.

## 2026-05-27 — Architecture (no component version change)

### Changed
- **Decided to re-found auth on session-less Ed25519 request signatures (`_internal/ARCHITECTURE.md` v2).**
  Investigation proved v1's model — logging the caller in as a WordPress user via
  `determine_current_user` — is *generally* incompatible with 2FA/security plugins,
  which discard the login within the same request (401 despite a valid token). The
  v2 design authorizes each *request* by detached signature in the
  `permission_callback`, never creates a WP session, and scopes operations to the
  enrolling user's capabilities via `user_can()`. The local MCP client holds the
  private key (decentralized, no central server in the daily path). Implementation
  pending (handed to the implementing agent). No code shipped in this entry.

## 2026-05-27 — connectmwp-agent 1.2.6

### Fixed
- **connectmwp-agent — every authenticated request self-destructed (401 despite a valid token).**
  `authenticate_request()` runs on `determine_current_user`, which WordPress
  evaluates more than once per request. The single-use replay nonce was claimed
  on the first pass (token recognized, "Last Used" stamped, user authenticated)
  and then **rejected on the second pass** — `add_option()` returns false for an
  already-claimed nonce — causing the filter to return `0` and reset the caller
  to logged-out. By the time the REST/AJAX permission check ran, the user was
  anonymous, so every call returned `rest_forbidden` (401) even for a full
  Administrator with a correct token. Fixed by memoizing the first successful
  token resolution per request (`$resolved_user_id`) and skipping the replay
  re-check on subsequent passes. Affects REST and Admin-AJAX paths alike.
  (`connectmwp-agent/connectmwp-agent.php`)

### Chore
- Synced the admin-page version badge to v1.2.6. Logged a follow-up (T007) to make
  that badge read from the plugin header so it can't drift again.

## 2026-05-27 — connectmwp-agent 1.2.5

### Fixed
- **connectmwp-agent — replace copy alerts with non-blocking inline toasts.** Replaced native browser `alert()` popups with a modern, clean inline toast notification. When copy buttons are clicked, a toast message fades in above the button and auto-fades out after 10 seconds. Re-packaged the WordPress agent plugin.

## 2026-05-27 — connectmwp-agent 1.2.4

### Chore
- **Bump version to 1.2.4.** Updated plugin version headers and dashboard elements to 1.2.4, aligning with the rebranding updates and security remediation fixes made earlier. Re-packaged the WordPress agent plugin.

## 2026-05-27 — connectmwp-mcp 1.2.5, connectmwp-server 1.2.5

### Fixed
- **connectmwp-server — resolve lint warnings & errors.** Cleared unused TS variables and catches in `ClientPage.tsx`. Replaced synchronous state rendering updates in `callback/page.tsx`'s `useEffect` hook with deferred asynchronous state updates to eliminate the React cascade render warnings and block build blocks.

### Chore
- **Completed folder-rename cleanup (`wpConnect` → `connectMWP`).** The project
  directory was renamed on disk; an audit confirmed all in-repo file paths and
  brand references already pointed to `connectMWP`. The one straggler was
  `connectmwp-mcp/package-lock.json`, which still carried the old self-name
  `wpconnect-mcp` (in `name` and `bin`) and a stale self-version `1.0.0`. Synced
  both to match `package.json` (`connectmwp-mcp` / 1.2.5). No functional change.
  (`connectmwp-mcp/package-lock.json`, `connectmwp-mcp/package.json`)

## 2026-05-26 — connectmwp-mcp 1.2.4, connectmwp-server 1.2.4

### Fixed
- **connectmwp-mcp — `get_posts` regression (broken core tool).** The over-fetching
  fix had `get_posts` send a JSON body on a GET request (rejected by native `fetch`)
  and append a query string to the endpoint that broke the admin-ajax fallback's
  action mapping, so the tool failed on both transports. GET params now travel only
  in the URL query string; `callWordPress` never sets a body on GET/HEAD; and the
  admin-ajax fallback splits the query string off before matching the action and
  forwards the params. (`connectmwp-mcp/index.js`)
- **connectmwp-server — unauthenticated SSRF in `/api/verify-site`.** The site-reachability
  probe fetched any user-supplied host server-side with no private-range checks,
  letting an unauthenticated caller probe the server's internal network and burn
  egress. Added private/loopback/link-local IP blocking (mirrors the MCP client's
  guard), internal-name rejection, pinned the Node.js runtime, and disabled
  redirect-following to prevent rebinding/redirect-to-internal. (`connectmwp-server/src/app/api/verify-site/route.ts`)

### Chore
- Cleaned trivial lint errors in the WIP (`markdown.ts` `let`→`const`, unused catch
  binding in the legal page). Synced server version display strings to 1.2.4.

> Note: `connectmwp-agent` remains at 1.2.3 (unchanged in this pass).
> The earlier security/architecture remediations (open redirect, fragment token
> transmission, atomic nonces, contributor publish checks, IP spoofing, MCP SSRF,
> media size limits, markdown SSOT extraction, typed site-verification errors)
> were verified resolved — see `_internal/REMEDIATION-VERIFICATION_2026-05-26_18-52.md`.
