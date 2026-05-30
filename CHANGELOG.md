# Changelog

All notable changes to connectMWP are recorded here. Each of the three
components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) carries
its own version; entries note which component changed.

## 2026-05-29 — v2.0.27

### Fixed — plugin data-integrity + performance (P7)

- **Data-loss race in paired-key storage (security/integrity, HIGH — T039).** Every paired client's key used to live in one shared database record that the plugin rewrote in full on each change. Under concurrent activity — for example a brand-new pairing arriving at the same instant an existing client made a request — one process could overwrite the other's change, silently dropping a just-paired key (it would show as "paired" on the user's machine but never actually authenticate) or even undoing a revoke. Each key now lives in its **own** database record, so a change to one key can no longer clobber another. Existing pairings are migrated automatically and **non-destructively** on upgrade — nothing the user set up before needs redoing, and the old combined record is kept (read-only) for one release as a safety net.

- **Slow "Paired Clients" settings page with many clients (cleanup, LOW — T043).** The plugin's admin settings screen looked up each paired client's WordPress user one at a time. It now fetches them all in a single query, so the page stays fast regardless of how many clients are paired. The table shows exactly the same information as before (login, display name, roles, the "Unknown User" fallback for a deleted user).

### Internal — P7

- **One key-storage data-access layer (DAL / SSOT).** All key reads and writes now go through a single set of helpers (`get_key` / `save_key` / `add_key` / `update_key_fields` / `delete_key` / `list_keys`, plus `index_add` / `index_remove` / `rebuild_key_index` / `key_option_name` / `normalize_key_record`). No code outside the DAL touches key storage directly — enforced by a grep gate in the verification harness. Per-key rows are the source of truth; a self-healing index lists the ids for cheap enumeration and is fully rebuildable from the rows.
- **Migration is one-time, sentinel-guarded (atomic `add_option`), and idempotent** (`maybe_migrate_legacy_keys`, fired on `plugins_loaded` so it runs on a plugin update; also lazily per-entry on read). It preserves all six stored fields per key (public key, bound user, label, created, last-used, last-IP) and **retains the legacy combined record this release** as a backward-read fallback.
- **Follow-up (v2.0.28):** drop the now-redundant legacy `connectmwp_keys` record after confirming all installs have migrated. Captured here so it is not forgotten.
- Added `_internal/verify/p7_test.sh`: an always-on static layer (DAL present, SSOT grep gate, atomic primitives, non-destructive migration, index recovery, batched settings render, auth-model invariants unchanged) plus a WP-CLI-gated behavioral layer (migration correctness, the concurrency race reproduction, and the T043 query-count proof) that skips cleanly when no WordPress is available.

### Changed — versioning

- **Bumped all three components to v2.0.27 (lockstep)** via the `/VERSION` SSOT + `scripts/sync-version.mjs`. Plugin zip rebuilt and mirrored to `connectmwp-server/public/` (sha-identical). All existing verification harnesses (`interop`, `sanitization`, `p2`–`p5`, `p6_idor`, `p6_enroll`) still pass.

## 2026-05-29 — v2.0.26

### Fixed — plugin security hardening (P6)

- **Private and trashed posts can no longer leak to under-privileged clients (T038, HIGH).** Reading a single post (`GET /connectmwp/v1/posts/<id>`, over both REST and the admin-AJAX fallback) now checks per-object read permission for **every** post status, not just drafts. Previously a key bound to a lower-privilege WordPress role (e.g. a Contributor) could fetch another author's *private* post, or any *trashed* post, and get the full body back — a broken object-level authorization (IDOR) gap. The fix routes every single-post read through one shared check that uses WordPress's own object-level read rule, so the answer matches exactly what that user would be allowed to read in the WordPress admin. Well-behaved Author/Editor/Administrator clients are unaffected; only the previously-leaking case now returns a 403. The list, update, and delete paths were already correct and gained regression coverage.

- **Malformed enrollment requests no longer create database rows (T041, MEDIUM).** The one-time pairing endpoint (`/enroll`) has a per-IP rate limiter. Previously, any request carrying a wrong-but-non-empty code wrote a rate-limit record to the database, so a flood of garbage codes from many source addresses could bloat the WordPress options table. Now a structurally-invalid or missing code is rejected up front with **zero** database writes; only a correctly-shaped (real or brute-forced) code counts against the 5-attempts-per-10-minutes limiter, exactly as before. The client-visible behavior of legitimate pairing is unchanged.

### Added — optional admin setting (P6 / T041)

- **New "Behind trusted proxy" setting (default OFF).** Under **Settings → connectMWP → Network & security**, an administrator can declare that the site sits behind a reverse proxy / CDN they control (Cloudflare, Nginx, a load balancer), so the enrollment limiter attributes requests to the real client IP from the forwarding headers. **Default is OFF**, in which case client IPs come from the direct connection and cannot be spoofed — so upgrading changes nothing unless you opt in. Can also be forced via `define('CONNECTMWP_TRUST_PROXY', true);` in `wp-config.php`. New OPERATIONS.md §8 documents this plus the recommended edge rate-limiting (the primary abuse control). Enabling it while *not* actually behind a controlled proxy re-introduces an IP-spoofing vector — leave it OFF if unsure.

### Changed — versioning

- **Bumped all three components to v2.0.26 (lockstep)** via the `/VERSION` SSOT + `scripts/sync-version.mjs`. Plugin zip rebuilt and mirrored to `connectmwp-server/public/` (sha-identical). New verification harnesses `_internal/verify/p6_idor_test.sh` and `_internal/verify/p6_enroll_test.sh` (+ `p6_enroll_shim.php`, `p6_idor_test.php`) added; the full existing harness suite (`interop`, `sanitization`, `p2`–`p5`) still passes.

## 2026-05-29 — v2.0.24

### Changed — module hygiene (P5 modularization step (iii))

- **connectmwp-mcp — extracted `lib/validators.js` (T144 step (iii)).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §1 (CRITICAL — Monolithic God File). The three input-validation functions — `isPrivateIp` (SSRF private/loopback/link-local IP classifier across IPv4, IPv6, and IPv4-mapped-IPv6 forms — T140), `validateImageUrl` (HTTPS-only + DNS-resolve + private-IP rejection that pins the safe IP for the anti-rebinding fetch — T140), and `validateImageMagicNumbers` (magic-number sniff guarding against arbitrary-file-read — I-2 Fix) — now live in one focused, header-documented module. `index.js` imports them and re-exports `isPrivateIp` / `validateImageUrl` / `validateImageMagicNumbers` for the verification harnesses. The now-dead `import dns from 'dns/promises'` was removed from `index.js` (`validateImageUrl` was its sole consumer). The monolith shrinks by ~125 lines.

  **No behavior change — function bodies moved verbatim; lockstep bump.** `bash _internal/verify/p2_test.sh` (the direct regression guard exercising `isPrivateIp` / `validateImageUrl` via the `index.js` import) and all five other harnesses still pass.

### Fixed — verification infra

- **`_internal/verify/sanitization_test.sh`** — fixed a pre-existing false-failure in the AC5 throw-site leak audit. Under bash `set -euo pipefail`, the middle `grep -E` returned exit 1 on a no-match (the correct/no-leak case), which aborted the whole script before AC5/success printed. Wrapped the matching grep so a no-match no longer poisons the pipeline (`| { grep -E "…" || true; } |`). Assertion logic and thresholds unchanged.

### Changed — documentation

- All "Verified against" anchors → v2.0.24.

### Bumped

- All three components → 2.0.24 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.23

### Changed — module hygiene (P5 modularization step (i) + (ii))

- **connectmwp-mcp — extracted `lib/constants.js` (T147).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §3 (MEDIUM — Hardcoded Fallbacks & Metadata). `MEDIA_MAX_BYTES`, `MEDIA_MAX_MB`, `ALLOWED_EXTENSIONS`, and `FALLBACK_VERSION` (the legacy `1.2.4` runtime fallback string) now live in a single named module with documentation of why each value is what it is. `index.js` imports the constants instead of declaring them inline. Future P5 steps will route additional configurables through the same module.

- **connectmwp-mcp — extracted `lib/crypto.js` with `buildCanonical()` + `signCanonical()` (T144 step (ii)).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §1 (CRITICAL — Monolithic God File). Before: `callWordPress` (REST) and `callWordPressAjax` (AJAX) each built the 6-field canonical inline and ran their own PEM-read + `crypto.sign` + try/catch. Two copies of the byte-identical-with-PHP signing primitive, two copies of the catch block routing through `sanitizeSigningError` + `logDiag`. After: `buildCanonical(parts)` joins the array with `'\n'` at a single named seam (documented as the byte-format invariant that must match the plugin); `signCanonical(canonical, privateKeyPath, ctx, deps)` reads the PEM, signs, returns base64, and funnels the error through dependency-injected helpers (the error helpers stay in index.js for v2.0.23; the next P5 step extracts them to `lib/errors.js`). The byte-format invariant now has ONE place to read.

  **Byte-identical with v2.0.22 — proved by harness.** `bash _internal/verify/interop_test.sh` still passes: Node signs, PHP reconstructs the canonical the same way, `sodium_crypto_sign_verify_detached` succeeds. `bash _internal/verify/p5_test.sh` adds explicit unit tests on `buildCanonical` (exact byte output for 3-part and 6-part inputs) and `signCanonical` (round-trip with a fresh keypair; sanitizer-wrapped error on bad path).

### Added — verification

- **`_internal/verify/p5_test.sh`** — 9-assertion proof of the extracted primitives. Run after any change to `lib/constants.js` or `lib/crypto.js`.
- **`_internal/verify/p2_test.sh` updated** — AC6 now expects 0 cap literals in `index.js` and 1 in `lib/constants.js` (the lift target). All other ACs unchanged.

### Changed — documentation

- All "Verified against" anchors → v2.0.23.

### Bumped

- All three components → 2.0.23 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.22

### Changed — BREAKING (response shape)

- **connectmwp-mcp — tool responses now flow through a projection layer that strips tautological fields and adds explicit pagination metadata (T143 + T148).** Source: ARCH-REVIEW-REPORT_2026-05-28_19-03.md §1 (HIGH — "Blind Proxy" Over-fetching) + §4 LOW (missing pagination safety on get_posts). New `connectmwp-mcp/lib/projections.js` module — pure functions, zero I/O, one projection per tool family — wired into every tool handler between `callWordPress` and `JSON.stringify`. Dropped fields by tool:

  - **All success responses (every tool):** the tautological `success: true` field is removed. The MCP envelope's absence-of-isError already signals success; carrying `success: true` on every response was redundant noise that the LLM had to read on every call.
  - **`connectmwp_get_post` / `connectmwp_get_posts` (post entities):** the duplicate `link` field is removed when it equals `url` (the plugin always sets both to the same permalink — carrying both wastes tokens linearly with post count).
  - **`connectmwp_create_post` / `connectmwp_update_post`:** same `link`/`url` dedupe when they match.

  Error responses (`success: false`) pass through unchanged so the `error` field remains the AI's diagnosis signal. Unrecognized shapes pass through unchanged — projection is never lossy (fail-safe).

  **Pagination metadata (T148):** `connectmwp_get_posts`, `connectmwp_list_tags`, `connectmwp_list_categories` now return a structured `pagination` object alongside the items array, replacing the flat `total` + `has_more` fields:
  ```json
  {
    "pagination": { "total": 247, "per_page": 50, "offset": 0, "next_offset": 50, "has_more": true },
    "posts": [...]
  }
  ```
  `next_offset` is `null` on the last page, so the AI can immediately invoke the next call (`connectmwp_get_posts({ offset: 50 })`) without asking the user "what's the next offset?" Offset-based per Q4.3 Option A (matches the WP REST native pagination shape; no premature cursor abstraction).

  Verified token-cost reduction: a representative 50-post `get_posts` response shrinks from 5214 bytes to 3816 bytes — **26.8% smaller** at the JSON layer alone. Larger savings on richer responses where `link`/`url` dedupe scales linearly. Verified by `bash _internal/verify/p4_test.sh` — 22+ assertions covering each tool, error pass-through, pagination shape on first/last pages.

  **Migration impact (Q4.2 Option C — hard cut + documented enumeration):** Any AI prompt or downstream workflow that explicitly reads `response.success`, `response.posts[].link`, `response.total`, or `response.has_more` needs to be updated. The new field paths are `response.posts`, `response.posts[].url`, `response.pagination.total`, `response.pagination.has_more`. Realistic affected count is near zero — the `_links`-style WP-internal fields the original audit flagged were already stripped by the plugin; this projection is the next layer of polish. No known customer-facing prompt relies on the dropped fields.

### Added — module hygiene

- **`connectmwp-mcp/lib/projections.js`** — first step of P5's modular `lib/` layer (`projectGetPosts`, `projectGetPost`, `projectMutatePost`, `projectDeletePost`, `projectUploadMedia`, `projectListTaxonomy`, `projectCreateTaxonomy`, `buildPagination`).
- **`package.json` `files` field** now includes `lib/**` so the lib/ tree ships in the npm tarball. Verified: `npm pack --dry-run` lists 4 files (`README.md`, `index.js`, `lib/projections.js`, `package.json`).

### Changed — documentation

- All "Verified against" anchors → v2.0.22.

### Bumped

- All three components → 2.0.22 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.21

### Security — HIGH

- **connectmwp-mcp — set 0600 on `~/.connectmwp.json` and 0700 on `~/.connectmwp/` (T149 + T150).** Source: SECURITY-REVIEW-REPORT_2026-05-28_18-58.md §3 (HIGH — Fix This Week). Previously the config file (containing `key_id`s, labels, and private-key paths) was created with the default umask perms (typically 0644) and the keystore directory at 0755 — both world-readable on a multi-user system or shared CI runner. Listing the directory leaked every paired host (one `<hostname>.ed25519` file per host). Two changes: `writeConfig` now passes `{ mode: 0o600 }` AND post-writes `fs.chmod(CONFIG_PATH, 0o600)` (covers the overwrite-existing case where mode is ignored). The add-site mkdir uses `{ recursive: true, mode: 0o700 }` AND chmod'd post-mkdir. A new `tightenPathPerms(targetPath, expectedMode)` helper does both the post-create chmod AND silently upgrades existing pre-v2.0.21 installs on the next `readConfig()` — emits one `[connectmwp:diag]` stderr line per tightening event (idempotent on already-tight installs, ENOENT swallowed silently). Windows is a no-op (NTFS doesn't honor POSIX mode bits; ACL-based perms are out of scope per Q3.1 Option A). Verified end-to-end: `bash _internal/verify/p3_test.sh` confirms 0644→0600 + 0755→0700 transitions, second-call idempotency, ENOENT swallowed.

### Added — module hygiene

- **`tightenPathPerms` exported** from `connectmwp-mcp/index.js` for verification harnesses + future test code.

### Changed — documentation

- `_internal/ARCHITECTURE.md` §8 security checklist — add line item for the perms tightening.
- All "Verified against" anchors → v2.0.21.

### Bumped

- All three components → 2.0.21 (lockstep). Plugin re-packaged in both mirrored locations (only the Version header changed; verifies sha-identical between root copy and `connectmwp-server/public/connectmwp-agent.zip`).

## 2026-05-28 — v2.0.20

### Security — CRITICAL

- **connectmwp-mcp — streamed media downloads + uploads with a hard 10MB cap enforced mid-stream (T139).** Source: SECURITY-REVIEW-REPORT_2026-05-28_18-58.md §2 (Incident-Class) + ARCH-REVIEW-REPORT_2026-05-28_19-03.md §2 (HIGH). The previous code path called `imgRes.arrayBuffer()` on the remote fetch response and `fs.readFile(file_path)` on local files, checking size only AFTER the entire payload was in memory — bypassed by chunked-encoded hostile streams with no `Content-Length` header (Node OOM / GC thrash within seconds of a 100MB+ stream). The new path uses a single `streamToCappedBuffer(stream, maxBytes)` helper that drains both Node Readable streams (`fs.createReadStream`) and Web ReadableStreams iteratively, throwing the moment cumulative bytes exceed `MEDIA_MAX_BYTES` and destroying the source so the socket/fd is released immediately rather than waiting for GC. Local files also get an `fs.stat` fast-path that rejects obvious oversized files before reading a single byte. Verified end-to-end: a 100MB chunked-encoded `Content-Length`-omitting hostile server is aborted at ~10MB transferred with RSS growth bounded under ~35MB; a 20MB local file is rejected with zero file reads. `MEDIA_MAX_BYTES` and `ALLOWED_EXTENSIONS` lifted to single top-of-file constants (one place to change; future P5 move to `lib/constants.js`).

- **connectmwp-mcp — pin the validated IP through the HTTP connect step to defeat DNS-rebinding SSRF (T140).** Source: SECURITY-REVIEW-REPORT_2026-05-28_18-58.md §2 (Incident-Class; OWASP API 2023 #7). Previously `validateImageUrl` resolved the hostname, checked the IP against the private-range blocklist, and trusted the URL string going forward — the subsequent `fetch(image_url)` did its OWN DNS resolution. A rebinding attacker controlled a hostname whose first lookup returned a safe public IP and whose second returned `127.0.0.1`, so validation passed and the fetch landed on the user's loopback. The new `pinnedHttpsGet(urlObj, validatedIp, family)` helper uses Node's built-in `https.request` with a `lookup` callback that returns the validation-time IP regardless of what DNS would say at connect time. TLS works naturally because `servername` is set to the URL's hostname (SNI uses the hostname, not the IP). `validateImageUrl` now returns `{ url, validatedIp, family }` instead of side-effecting only. The `isPrivateIp` blocklist was also extended to recognize IPv4-mapped IPv6 forms (`::ffff:127.0.0.1` and similar — a common attacker bypass), the `0.0.0.0/8` block, IPv6 link-local (`fe80::/10`), and IPv6 unique-local (`fc00::/7`). Verified by 22-case unit test of `isPrivateIp` plus a live in-process server that proves the lookup-callback pin lands on the pinned IP, not the system-resolved one.

### Added — module hygiene

- **`isMainModule()` guard around `run()`** so importing `connectmwp-mcp/index.js` from a test harness (or other module) does NOT auto-spawn the MCP stdio server. The bin entrypoint still boots normally — both the direct-node and symlinked-bin invocation paths are handled via `realpathSync`-resolved comparison. Enables clean unit testing of the exported helpers from verification scripts without spawning a stdio server.
- **Exported internal helpers for verification harnesses:** `isPrivateIp`, `streamToCappedBuffer`, `sanitizeSigningError`, `pinnedHttpsGet`, `validateImageUrl`, `MEDIA_MAX_BYTES`, `ALLOWED_EXTENSIONS`. Not part of the public MCP tool surface; subject to P5 modularization.
- **`_internal/verify/p2_test.sh`** — runnable proof of T139 + T140 closure (AC1 streaming abort, AC2 fs.stat fast-path, AC3 IP pinning lands on pinned IP, AC4 22-case IPv6/IPv4-private-range, AC6 constants externalized). Exits non-zero on any regression.

### Changed — documentation

- **`_internal/ARCHITECTURE.md` §8 security checklist** — two more boxes flipped to `[x]` (DNS rebinding closed via IP pinning; media downloads / uploads streamed with hard cap).
- All "Verified against" anchors → v2.0.20 (`CLAUDE.md` project, `OPERATIONS.md`, `SUPPORT_TRAINING.md`, `_internal/ARCHITECTURE.md`).
- `README.md` version line → v2.0.20.

### Bumped

- All three components → 2.0.20 (lockstep). Plugin re-packaged in both mirrored locations (only the Version header changed; verifies sha-identical between root copy and `connectmwp-server/public/connectmwp-agent.zip`).

## 2026-05-28 — v2.0.19

### Security — CRITICAL

- **connectmwp-agent + connectmwp-mcp — close the request-replay window via per-request nonce in the Ed25519 canonical (T137).** Source: `_internal/SECURITY-REVIEW-REPORT_2026-05-28_18-58.md` §1 — broken authentication via missing nonce; OWASP API 2023 #2 + #6. The MCP client now generates a fresh RFC 4122 UUID per request (`crypto.randomUUID()`), sends it in a new `X-ConnectMWP-Nonce` header, and includes it in the canonical signing string at position 2 (between timestamp and method). The plugin extracts the header, validates the UUID shape, and rebuilds the canonical with the nonce in the same position before verifying the Ed25519 signature. The existing sig-hash replay cache (`is_replay_signature` / `cmwp_sig_*` options) is preserved as defense-in-depth — nonce uniqueness makes every signature unique by construction, so the cache continues to catch any literal-replay attempt naturally. **Breaking — hard cut:** v2.0.19 plugin rejects any request without a nonce header with HTTP 401 + error code `connectmwp_missing_nonce`. Pre-v2.0.19 MCP clients fail loudly with a specific code so support can recognize "pinned-old-client" at a glance. No customer-facing docs instruct version pinning (verified at planning time); the recommended `npx -y connectmwp-mcp` auto-pulls the new client. The README's "replay protection is active" claim is now structurally backed by the canonical's nonce field, not just by the after-the-fact sig-hash cache.

- **connectmwp-mcp — sanitize private-key filesystem path out of signing-failure error messages (T138).** Source: same security report §1 — OWASP API 2023 #10 (Unsafe Consumption of APIs). The two former throw sites in `callWordPress` and `callWordPressAjax` interpolated `privateKeyPath` directly into the error message returned to the AI client, leaking the keystore filesystem location into LLM context, chat transcripts, and any client-side logs. New `sanitizeSigningError(err)` helper returns a stable user-facing message per `err.code` (`ENOENT` / `EACCES` / `EPERM` / parse-failure) with the actionable recovery command (`npx -y connectmwp-mcp add-site --enroll …`). A separate `logDiag(msg)` helper writes the full original message (including the path) to stderr with a `[connectmwp:diag]` prefix — captured by the MCP client as an out-of-band log channel, never parsed as JSON-RPC protocol traffic. Stderr safety verified against `@modelcontextprotocol/sdk` StdioServerTransport source (stdout is JSON-RPC exclusive). Full audit of 21 `throw new Error` sites in `index.js` confirms only these two sites were Class A (leaking internal state); all other sites echo only user-supplied values or constant strings. Audit table in `_internal/PLAN_T138_2026-05-28_21-26-39.md` §4.

### Added — diagnostic surface

- **connectmwp-agent — distinguishable WP_Error codes on every verification-failure path** (`connectmwp_missing_nonce`, `connectmwp_invalid_nonce_format`, `connectmwp_missing_credentials`, `connectmwp_timestamp_skew`, `connectmwp_unknown_key`, `connectmwp_malformed_credentials`, `connectmwp_sodium_missing`, `connectmwp_signature_invalid`, `connectmwp_replay_detected`). New private `describe_verification_error($code)` method maps each code to a safe human-readable message (codes are not secrets — the caller can already see the URL, headers, and timestamp). Surfaced through both `central_rest_auth` (REST path → WP_Error) and `handle_ajax_request` (AJAX fallback → wp_send_json_error with `code` + `message` fields). Eliminates the previous generic "Unauthorized" / 401 that masked which check failed.

### Added — interop verification harness

- **`_internal/verify/interop_test.sh`** — runnable Node↔PHP byte-identical canonical proof. Generates a fresh Ed25519 keypair in Node, signs a sample canonical including the nonce, hands the signature + public key to PHP, has PHP reconstruct the canonical the SAME way and verify via `sodium_crypto_sign_verify_detached`. Also asserts AC1 (two different nonces produce different signatures) and Ed25519 determinism (same input → same signature, which is what the sig-hash replay cache relies on).
- **`_internal/verify/sanitization_test.sh`** — runnable T138 sanitization proof. Forces three failure modes (ENOENT, EACCES, PEM-parse) and asserts: user-facing message has no filesystem path; recovery command is present; operator stderr preserves the full path + diagnostic prefix; zero throw sites in `index.js` still reference `privateKeyPath` / `/Users/` / `.ed25519`.

### Changed — documentation

- **`_internal/ARCHITECTURE.md` §4.3 (canonical signing string), §4.4 (verification order), §8 (security hardening checklist).** Canonical template now lists `nonce` as the second field. Verified-against anchor bumped to v2.0.19.
- **`CLAUDE.md` (project) §"Daily runtime path".** Custom-headers list expanded from three to four (`X-ConnectMWP-Key`, `-Timestamp`, `-Nonce`, `-Signature`).
- **`README.md`** — replay-protection sentence updated from generic to concrete (cites the nonce position in the canonical). Version line bumped.
- **`SUPPORT_TRAINING.md`** — new troubleshooting row for the `connectmwp_missing_nonce` 401-with-specific-code symptom (recognize pinned-old-client). Verified-against anchor bumped to v2.0.19.
- **`OPERATIONS.md`** — new section "Replay-blocked verification (T137)" with a copy-paste curl recipe so anyone can confirm the replay window is closed against a paired live site.

### Bumped

- All three components → 2.0.19 (lockstep). Plugin re-packaged in both mirrored locations (root copy gitignored; `connectmwp-server/public/connectmwp-agent.zip` committed; sha-identical to root).

## 2026-05-28 — v2.0.18

### Changed
- **connectmwp-agent — complete redesign of the WP Admin Settings page** following the "calm device-management" point of view (GitHub SSH Keys / Apple Family Sharing aesthetic, not WP-admin-table-busy). Approved design + decision log archived at `_internal/design_pairing_page_v2_2026-05-28/`. Specifically:
  - **State-aware layout** — the page now branches on `$page_state` ∈ {`zero`, `mid-pair`, `paired`}. Zero-state shows a full-card Get Started panel; mid-pair leads with the pairing card; paired leads with the AI clients list.
  - **Status-first information flow** (inverted from old "configure → status" order): the paired-clients list is the centerpiece; the "+ Pair another" button lives in its header; the IDE config sits below as a tinted reference surface.
  - **Per-row status dots** replace the standalone green "Connection Status" banner. Green dot for healthy, grey for stale (no use in 30 days OR never-used + > 7d old). Status is communicated at the row level so it scales to 1, 5, or 50 clients without layout change.
  - **Two-row client cards** in a bordered list with subtle alternating-row backgrounds (`#fff` / `#fbfcfd`) + hairline separators + hover lighten. Row 1: dot + label + optional JUST PAIRED badge + right-aligned Revoke. Row 2 (meta): "paired DATE TIME as USER · last used DATE TIME" + a smaller muted line with the `cmwp_key_…` chip.
  - **Exact timestamps** in `YYYY-MM-DD HH:MM` format, parsed via `wp_timezone()` + `DateTimeImmutable::createFromFormat` (the v2.0.17 fix). Bolded so they read above the muted meta text. Relative phrasings ("X ago") removed from data display — kept only in the transient "What now?" copy. Timezone disclaimer added below the list.
  - **Click-to-copy on key_id chips** with toast confirmation (reuses the existing `showConnectMWPToast` helper).
  - **Tabbed Configure card** (Claude Desktop / Cursor / Other) on a subtle blue-tinted surface (`#f6f9fc`). Replaces the previous side-by-side Cursor + Claude Desktop JSON stack — ~60% less vertical footprint, adds room for ChatGPT Desktop / Cline / Continue without growing the page.
  - **Hero preserved** (deliberate, called "decent" in feedback) with version badge and copy refined to mention more AI clients (ChatGPT Desktop, Antigravity).
  - **Auto-refresh pairing-status polling** from v2.0.16 carried forward unchanged in the mid-pair state's pairing card.
  - **Responsive collapse** at ≤600px: client rows stack to a single column (label / meta / action), pairing-card command-button stacks vertically.

### Bumped
- All three components → 2.0.18 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.17

### Fixed
- **connectmwp-agent — "paired X ago" relative-time label in the Connection Status banner was offset by the WP-vs-server timezone delta.** `current_time('mysql')` stores the key's `created` field in the WP-configured timezone with NO timezone marker on the string. The render code then parsed it with bare `strtotime()`, which silently interprets it as the PHP-server timezone (usually UTC). On a Central-Time WP site sitting on a UTC server, a freshly-paired key displayed "paired 6 hours ago" instead of "just now" — exactly the UTC-CT offset. Reproduced live on 2morrow.ai immediately after the v2.0.16 deploy. Fixed by parsing `created` explicitly with `wp_timezone()` via `DateTimeImmutable::createFromFormat` so the resulting Unix timestamp is correct regardless of how WP and the hosting server's timezones relate. Falls back to the old `strtotime()` path on pre-WP-5.3 installs (where `wp_timezone()` doesn't exist). (`connectmwp-agent/connectmwp-agent.php` — `render_settings_page`)

### Bumped
- All three components → 2.0.17 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.16

### Added
- **connectmwp-agent — live pairing-status polling on the settings page.** When a pairing code is visible, the page now polls a tiny admin-only AJAX endpoint (`action=connectmwp_pairing_status`, nonced, gated by `current_user_can('manage_options')`) every 3 seconds AND immediately on `visibilitychange` (when the tab regains focus — typical when the user returns from their terminal). On detecting a new key (total grew or latest_key_id changed), the pairing card flips to a green "🎉 Pairing successful!" state and reloads after 1.5s so the full new layout (Connection Status banner, "What now?" panel, highlighted Paired Clients row) appears without the user having to manually refresh. Stops polling on success, code expiry, or hidden tab. The success-card DOM is built with `createElement` + `textContent` (no `innerHTML`) so the server-supplied label is structurally XSS-safe regardless of upstream sanitization. (`connectmwp-agent.php` — `pairing_status_handler`, polling JS in `render_settings_page`)

### Bumped
- All three components → 2.0.16 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-28 — v2.0.15

### Added
- **connectmwp-agent — `Connection Status` banner at the top of the plugin settings page.** Bluetooth-style "you are connected" feedback. Green when 1+ clients are paired, with a count and the most-recent label/time. Neutral gray when no clients are paired. Visible on every page load, not just immediately after pairing. (`connectmwp-agent/connectmwp-agent.php` — `render_settings_page`)
- **connectmwp-agent — `"What now?"` panel** shown for ~1 hour after the most-recent pairing. Confirms identity ("You can now read/write `<site>` as `<display name>` (`<login>`, role: `<roles>`)"), gives a test-it prompt (`"list the tags on this site using connectMWP"`), warns about the AI-client restart-to-reconnect case, and explains how to register the same MCP server in other AI clients (Claude Desktop / Cursor / ChatGPT Desktop / Antigravity) sharing the same pairing.
- **connectmwp-agent — most-recent row highlighted** in the Paired Clients table (green left-border + "✓ new" badge) while the What now? panel is visible. Table is also now sorted newest-first by `created`.
- **connectmwp-agent — `/connectmwp/v1/whoami` REST endpoint** (and `connectmwp_action=whoami` AJAX equivalent). Signature-authenticated, no capability check required. Returns the same identity payload as `/enroll`: `{ site: {title,url}, user: {login,display_name,roles}, capabilities: {edit_posts,publish_posts,…} }`. Used by the MCP client to verify end-to-end signing works post-pairing and by support/diagnostics to confirm what user/capabilities a key resolves to. (`build_identity_payload`, `whoami_handler`, `check_signature_only`)
- **connectmwp-agent — `/enroll` response enriched** with the same identity payload, so the pairing CLI can show a friendly confirmation without an additional round-trip if the round-trip itself fails.
- **connectmwp-mcp — post-pairing /whoami round-trip + enriched CLI summary.** After a successful enrollment, the client now signs a `GET /whoami` request with the brand-new key, prints `✓ Connected to "<Site Title>" (<site_url>) / ✓ Acting as: <Display Name> (<login>) — <roles> / ✓ Can: <friendly capability list> / ✓ Key ID / ✓ Label / ✓ Set as default site` and a test-it prompt. Falls back to the enroll-response payload (with a warning) if the round-trip fails. (`printPairingSummary` helper, `index.js`)
- **connectmwp-mcp — AJAX action mapping** for the new `whoami` endpoint, so the round-trip works on hosts where REST is blocked but admin-ajax isn't.

### Bumped
- All three components → 2.0.15 (lockstep). Plugin re-packaged in both mirrored locations.

## 2026-05-27 — v2.0.14

### Fixed
- **connectmwp-agent — Terminal Pairing Command textarea rendered white-on-white (invisible).** The
  `.cmwp-cmd-textarea` rule was outranked by WordPress admin's `.wrap textarea` selector (same class
  specificity, loaded later globally), so the textarea fell back to WP's default light styling and the
  dark-blue background never applied — making the npx command unreadable even though it was present
  in the DOM (confirmed: selecting the textarea revealed the text). Bumped the selector specificity to
  `.cmwp-wrap textarea.cmwp-cmd-textarea` and added `!important` on `background`/`color` as
  belt-and-suspenders. (`connectmwp-agent/connectmwp-agent.php`)

### Verified (live)
- **v2.0.12 cache-bypass fix confirmed effective on 2morrow.ai.** Authenticated GET emits
  `Cache-Control: no-store, no-cache, must-revalidate, max-age=0, no-store, private` +
  `X-LiteSpeed-Cache-Control: no-cache`; LiteSpeed no longer caches the response
  (`x-litespeed-cache` empty); an immediate unauthenticated request to the same fresh URL returns
  `401 connectmwp_unauthorized` with no leaked data.

### Bumped
- All three components → 2.0.14 (lockstep). Plugin re-packaged.

## 2026-05-27 — v2.0.13

Remediation pass for the day's security & architecture reviews. All three components bumped in
lockstep to 2.0.13 (supersedes the interim working labels 2.0.11/2.0.12).

### Fixed (CRITICAL — found in live testing)
- **connectmwp-agent — unauthenticated draft/content disclosure via edge cache (cache-based auth bypass).**
  On LiteSpeed (common on managed hosts), signed REST **GET** responses were cached and served to
  **unauthenticated** callers hitting the same URL, bypassing the central signature check. Proven live: an
  authenticated `GET /posts` (cache miss, 3 drafts) followed by an unauthenticated request to the same URL
  returned `200` (`x-litespeed-cache: hit`) with those **draft** titles. Root cause: the session-less model
  means WordPress doesn't auto-emit `no-cache`. Fixed by forcing no-store/no-cache on every `connectmwp/v1`
  response (`DONOTCACHEPAGE`, `nocache_headers()`, `Cache-Control: no-store`, `X-LiteSpeed-Cache-Control:
  no-cache`, and the `litespeed_control_set_nocache` action) in `central_rest_auth`.
  **Deploy note:** existing cached entries persist (TTL up to 7 days) — purge the LiteSpeed cache after deploying.

### Fixed
- **connectmwp-mcp — a failed `add-site --enroll` destroyed the existing working key (data-loss).** The enroll
  flow overwrote the site's key before contacting the server and `unlink`ed it on failure, so a failed re-pair
  (e.g. an expired/used 10-minute code) left no usable key. Fixed to stage the new key at a temp path and only
  `rename` it into place after enrollment succeeds; failures remove only the temp key. (`connectmwp-mcp/index.js`)
- **connectmwp-server — legal pages broken by the v2.0.10 CSS migration (regression).** The Tailwind migration
  deleted ~596 lines of `globals.css` but not `legal/[slug]/page.tsx`, which still referenced the removed
  classes — leaving `/legal/privacy|terms|about` unstyled. Rewrote the legal page in Tailwind and replaced a
  stale hardcoded `v1.2.4` badge with the dynamic package version. (`connectmwp-server/src/app/legal/[slug]/page.tsx`)
- **connectmwp-agent — PHP 8.4 implicit-nullable deprecations.** `get_tags_handler`/`get_categories_handler`
  used `WP_REST_Request $request = null` (E_DEPRECATED on 8.4, fatal in PHP 9). Changed to `?WP_REST_Request`.
  Surfaced by `php -l`. (`connectmwp-agent/connectmwp-agent.php`)

### Verified (no change needed)
- The dev's v2.0.10 remediation was reviewed and confirmed correct: central `rest_pre_dispatch` auth is
  namespace-scoped (won't break the site's wider REST API); the replay claim is atomic (`add_option`) with a
  per-request memo preventing double-claim; the multipart body hash is verified against `hash_file()` of the
  actual upload. Live sweep passed term/post pagination, write-replay rejection, and create/delete.
- Backlog (deferred to avoid churn in a security release): magic-number constants, MCP empty-catch logging.

## 2026-05-27 — connectmwp-mcp 2.0.11

### Fixed (data-loss bug)
- **connectmwp-mcp — a failed `add-site --enroll` destroyed the existing working key.** The enroll flow
  wrote the new private key directly over the site's existing key *before* contacting the server, and the
  failure path then `unlink`ed it — so any failed re-pair (e.g. an expired/already-used 10-minute pairing
  code) left the site with **no** usable key (worse than before the attempt). This bit a live session:
  re-running the enroll command with a stale code wiped the working pairing. Fixed to write the new key to
  a temp path and only `rename` it into place **after** enrollment succeeds; the failure path removes only
  the temp key and never touches an existing working key. (`connectmwp-mcp/index.js`)

## 2026-05-27 — connectmwp-agent 2.0.12

### Fixed (CRITICAL — found in live testing)
- **connectmwp-agent — unauthenticated draft/content disclosure via edge cache (cache-based auth bypass).**
  Live testing on 2morrow.ai (LiteSpeed) showed that signed REST **GET** responses were being cached by
  LiteSpeed and then served to **unauthenticated** callers hitting the same URL — bypassing the central
  signature check entirely. Proven: an authenticated `GET /posts` (cache miss) returned 3 drafts; an
  immediate unauthenticated request to the same URL returned `200` (`x-litespeed-cache: hit`) with those
  same **draft** titles. Root cause is a side effect of the session-less model — WordPress only auto-emits
  `no-cache` for *logged-in* REST requests, so session-less signed responses were cacheable. Fixed by
  forcing no-store/no-cache on every `connectmwp/v1` response (`DONOTCACHEPAGE`, `nocache_headers()`,
  explicit `Cache-Control: no-store`, `X-LiteSpeed-Cache-Control: no-cache`, and the authoritative
  `litespeed_control_set_nocache` action) in `central_rest_auth`. (`connectmwp-agent/connectmwp-agent.php`)
  **Deploy note:** existing cached entries persist (TTL up to 7 days) — the LiteSpeed cache must be
  **purged** after deploying this build, then re-verified.

## 2026-05-27 — connectmwp-server 2.0.11, connectmwp-agent 2.0.11

### Fixed
- **connectmwp-server — legal pages broken by the v2.0.10 CSS migration (regression).** The v2.0.10
  commit converted `ClientPage` to Tailwind and deleted ~596 lines of `globals.css`, but did not
  update `legal/[slug]/page.tsx`, which still referenced the now-deleted semantic classes
  (`app-container`, `legal-card-container`, `legal-content`, …) — leaving `/legal/privacy|terms|about`
  unstyled. Rewrote the legal page in Tailwind (consistent with `ClientPage`) and replaced a stale
  hardcoded `connectMWP v1.2.4` badge with the dynamic `package.json` version.
  (`connectmwp-server/src/app/legal/[slug]/page.tsx`)
- **connectmwp-agent — PHP 8.4 implicit-nullable deprecations.** `get_tags_handler` and
  `get_categories_handler` declared `WP_REST_Request $request = null` (implicitly nullable), which
  emits `E_DEPRECATED` on PHP 8.4+ (the target host runs 8.4) and becomes a fatal in PHP 9. Changed to
  explicit `?WP_REST_Request`. Surfaced by `php -l` (the original author had no local PHP).
  (`connectmwp-agent/connectmwp-agent.php`)

### Note
- Completed the dev's v2.0.10 review-remediation pass: verified the central `rest_pre_dispatch` auth
  filter is correctly namespace-scoped (won't break the site's wider REST API), the replay claim is
  atomic (`add_option`) with a per-request memo preventing double-claim, and the multipart body hash
  is verified against `hash_file()` of the actual upload. `connectmwp-mcp` left at 2.0.10 (unchanged).
  Optional cosmetic items (magic-number constants, empty-catch logging) left as backlog to avoid
  churn in a security release.

## 2026-05-27 — v2.0.10

### Fixed
- **connectmwp-agent — secure body hash for multipart uploads.** Enabled body hash header verification (`X-ConnectMWP-Body-Hash`) on `multipart/form-data` uploads (e.g. image uploads) to prevent file intercept/tampering.
- **connectmwp-agent — enrollment rate limiting & SSL enforcement.** Restructured public endpoint `enroll_client_handler` to enforce HTTPS (except localhost) and apply transient-based IP rate limits.
- **connectmwp-agent — correct delete cap.** Gated AJAX fallback deletion on actual `delete_post` user capability instead of generic `edit_post` capability.
- **connectmwp-agent & connectmwp-mcp — paginated list endpoints.** Added support for `limit`, `offset`, and `search` query parameters in tags/categories listing routes to prevent unbounded memory/context issues, and `offset` in post retrieval.
- **connectmwp-mcp — SSRF redirect bypass block.** Disabled automatic redirect following (`redirect: 'manual'`) during image URL downloading, preventing local host port/metadata scans.
- **connectmwp-mcp — arbitrary file disclosure prevention.** Added image buffer magic number validation during uploads to block arbitrary file disclosures via tricky filenames/extensions.
- **connectmwp-server — Tailwind CSS refactor.** Converted custom CSS layout classes inside `ClientPage.tsx` to utility Tailwind CSS layout classes, and cleaned up `globals.css`.

### Chore
- Bumped versions of all components (`connectmwp-agent`, `connectmwp-mcp`, `connectmwp-server`) to `2.0.10`.

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
