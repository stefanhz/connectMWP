# Changelog

All notable changes to connectMWP are recorded here. Each of the three
components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) carries
its own version; entries note which component changed.

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
