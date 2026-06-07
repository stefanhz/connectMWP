<?php
/**
 * Plugin Name: connectMWP
 * Plugin URI: https://connectmwp.com
 * Description: Securely let your own local AI client (Claude, Cursor) publish to this WordPress site over a signed, session-less Ed25519 connection — no login, no central server.
 * Version: 2.3.10
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Stefan Heinz, 2morrow.ai
 * Author URI: https://2morrow.ai
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: connectmwp
 */

defined('ABSPATH') || exit;

class ConnectMWP_Agent {

    /**
     * Plugin version. SINGLE SOURCE OF TRUTH is the `Version:` header at the top
     * of this file (itself propagated from the repo-root /VERSION file by
     * scripts/sync-version.mjs). Read at runtime via get_file_data() and cached
     * in a static, so the plugin carries no second version literal to drift.
     * Replaces the former `const VERSION`.
     */
    private static $version_cache = null;
    public static function version() {
        if (self::$version_cache === null) {
            if (!function_exists('get_file_data')) {
                require_once ABSPATH . 'wp-includes/functions.php';
            }
            $data = get_file_data(__FILE__, ['Version' => 'Version']);
            self::$version_cache = !empty($data['Version']) ? $data['Version'] : 'unknown';
        }
        return self::$version_cache;
    }

    const OPTION_TOKENS = 'connectmwp_agent_tokens';
    const OPTION_NONCES = 'connectmwp_agent_nonces';
    const API_NAMESPACE = 'connectmwp/v1';

    // ---- Key storage DAL constants (T039) ----------------------------------
    // Keys were historically stored as ONE monolithic associative-array option
    // (`connectmwp_keys`), mutated via non-atomic read-modify-write — a TOCTOU
    // race that could silently drop a concurrently-enrolled key. As of v2.0.27
    // each key lives in its OWN option row so a write to one key can never
    // clobber another. A self-healing index option lists the key ids for cheap
    // enumeration (the per-key rows remain the source of truth). The legacy
    // monolithic row is retained for one release as a backward-read fallback and
    // is dropped in a follow-up release (v2.0.28) — see CHANGELOG.
    const LEGACY_KEYS_OPTION = 'connectmwp_keys';        // read-only fallback (one release)
    const KEY_OPTION_PREFIX  = 'connectmwp_key_';        // + bare hex suffix => per-key option name
    const KEY_INDEX_OPTION   = 'connectmwp_key_index';   // array of key_id (hint, self-healing)
    const KEY_PREFIX_STRIP   = 'cmwp_key_';              // stripped from key_id to form the option suffix
    const KEY_MIGRATED_FLAG  = 'connectmwp_keys_migrated'; // migration sentinel (atomic add_option)
    const KEY_INDEX_MAX_RETRY = 5;                       // bounded optimistic-retry for the index option

    // Pairing-poll "latest client" hint (T058). The settings page polls every 3s
    // during a pairing window; resolving every key row each poll is an O(N) option
    // fan-out. This denormalized hint lets the poll read the newest client from
    // ONE option (total comes from the index length), falling back to the
    // authoritative list_keys() only when the hint is absent. Name deliberately
    // avoids the `connectmwp_key_` prefix so the index-rebuild LIKE scan can never
    // mistake it for a key row.
    const LATEST_CLIENT_OPTION = 'connectmwp_latest_client';

    // ---- ChatGPT API-token storage DAL constants (T1) ----------------------
    // ChatGPT cannot perform device-key Ed25519 signing, so it authenticates
    // with a per-site bearer-style API token instead. Tokens use the SAME atomic
    // per-row + self-healing-index design as the key DAL above (one option row
    // per token, autoload `no`, plus a non-authoritative rebuildable index) so a
    // write to one token can never clobber another (TOCTOU-safe). The store is a
    // SEPARATE namespace (`connectmwp_cgpt_token_*`) so it can never collide with
    // the `connectmwp_key_*` rows or the index-rebuild LIKE scan. Only the
    // sha256 hash of a token is ever persisted — the plaintext exists exactly
    // once, at mint time, and is never stored or logged.
    const CGPT_TOKEN_OPTION_PREFIX = 'connectmwp_cgpt_token_'; // + bare hex suffix => per-token option name
    const CGPT_TOKEN_INDEX_OPTION  = 'connectmwp_cgpt_token_index'; // array of token_id (hint, self-healing)
    const CGPT_TOKEN_ID_PREFIX     = 'cmwp_cgpt_';            // token_id prefix (also the plaintext prefix)
    const CGPT_TOKEN_SECRET_BYTES  = 32;                      // entropy of the token secret (>= 32 random bytes)
    const MAX_CGPT_TOKENS_PER_SITE = 20;                      // (VR-2) hard cap on live ChatGPT tokens per site; admin must revoke before minting #21

    // Path-token fallback opt-in. The `/mcp/<token>` route embeds the live bearer
    // token in the URL, which lands in server/CDN access logs (sec review MEDIUM).
    // It is therefore OFF by default: the route param is only honored as an auth
    // source, and the path-token connector URL is only surfaced in the admin UI,
    // when an admin has explicitly enabled this option after reading the
    // log-exposure warning. The two HEADER sources always work regardless.
    const CGPT_ALLOW_PATH_TOKEN_OPTION = 'connectmwp_cgpt_allow_path_token'; // boolean WP option, DEFAULT false

    // ChatGPT bearer-token verifier IP throttle (T3). Mirrors the enroll
    // limiter (cmwp_enroll_limit_*): only FAILED resolves count toward the
    // limit, so a legitimate client making many authenticated calls is never
    // penalized. Once CGPT_AUTH_MAX_FAILURES failed attempts accumulate from
    // one IP within CGPT_AUTH_LOCKOUT_SECONDS, further attempts from that IP
    // are rejected until the transient expires. The key hashes the IP so no
    // raw PII lands in the option name.
    const CGPT_AUTH_MAX_FAILURES   = 10;   // failed-resolve attempts per IP before lockout
    const CGPT_AUTH_LOCKOUT_SECONDS = 600; // lockout / failure-count window (10 min)

    // [OAuth Phase 2] /oauth/token per-IP failure limiter (M-rate). Mirrors the
    // cgpt verifier limiter: only FAILED grants count, successful exchanges are
    // never penalized. Defense-in-depth/DoS — the 256-bit token entropy already
    // makes brute force infeasible, but the limiter caps abusive request volume.
    // Hashed-IP key (cmwp_oauth_token_limit_<md5(ip)>), same budget/window
    // constants spirit as the cgpt limiter but declared separately so the two
    // credential classes can be tuned independently.
    const OAUTH_TOKEN_MAX_FAILURES    = 20;  // failed grant attempts per IP before lockout
    const OAUTH_TOKEN_LOCKOUT_SECONDS = 600; // lockout / failure-count window (10 min)

    // Wire-format length of an enrollment code: bin2hex(random_bytes(16)) yields
    // exactly 32 lowercase hex chars (see generate_enrollment_code()). Declared
    // once so the mint side and the structural validator cannot drift (T041).
    const ENROLL_CODE_HEX_LEN = 32;

    // Pagination limits — SSOT for list endpoints (T052). Posts cap (100) and
    // taxonomy cap (200) are deliberately distinct: post rows may carry content
    // (large), so they get a tighter ceiling. MAX_PER_PAGE / DEFAULT_PER_PAGE
    // mirror the "default 50, max 200" contract the MCP client advertises for
    // tags/categories; keep them in agreement (guarded by p9_test.sh).
    const DEFAULT_PER_PAGE   = 50;   // default page size for all list endpoints
    const MAX_PER_PAGE       = 200;  // cap for taxonomy lists (matches MCP tag/category contract)
    const MAX_PER_PAGE_POSTS = 100;  // cap for post lists (rows may carry content)
    const MIN_PER_PAGE       = 1;    // hard lower bound for any list page size

    // Media upload size cap (T057) — SSOT mirror of the MCP client's
    // MEDIA_MAX_BYTES (connectmwp-mcp/lib/constants.js). There is NO compile-time
    // link between the two languages, so they MUST be changed together — see the
    // cross-language contract note in CLAUDE.md.
    const MEDIA_MAX_BYTES = 10 * 1024 * 1024; // 10 MB
    const MEDIA_MAX_MB    = 10;

    // MCP/JSON-RPC request body ceiling. The /mcp endpoint carries only JSON-RPC
    // envelopes (tool args, post content) — never file bytes — so 2 MB comfortably
    // covers any real post while bounding parse cost on a token-authenticated route.
    const MCP_MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB

    // Signature-verification timing, seconds (T060). INVARIANT:
    // REPLAY_TTL_SECONDS MUST exceed TIMESTAMP_SKEW_SECONDS — otherwise a
    // signature can age out of the replay cache while still inside the accepted
    // clock-skew window, reopening the replay hole. Do not narrow this gap.
    const TIMESTAMP_SKEW_SECONDS     = 300; // ± window on X-ConnectMWP-Timestamp
    const REPLAY_TTL_SECONDS         = 360; // sig-hash replay cache lifetime (> skew)
    const LAST_USED_THROTTLE_SECONDS = 60;  // min interval between last_used writes

    // Client-status display thresholds, seconds (T060) — used by the settings page.
    const JUST_PAIRED_SECONDS     = 3600;       // < 1h old → JUST PAIRED badge
    const STALE_UNUSED_SECONDS    = 7 * 86400;  // never used + older than this → stale
    const STALE_LAST_USED_SECONDS = 30 * 86400; // last use older than this → stale

    private static $instance = null;

    // Per-request memo of a successful token authentication. determine_current_user
    // can be evaluated multiple times in a single request; our replay nonce is
    // single-use, so re-validating on a later pass would fail and silently
    // de-authenticate the user. Resolve once, then reuse for the rest of the request.
    private $resolved_user_id = 0;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Register REST endpoints
        add_action('rest_api_init', [$this, 'register_rest_routes']);

        // Central REST signature validation filter
        add_filter('rest_pre_dispatch', [$this, 'central_rest_auth'], 10, 3);

        // Admin-AJAX routes (Fallback endpoints)
        add_action('wp_ajax_connectmwp_api', [$this, 'handle_ajax_request']);
        add_action('wp_ajax_nopriv_connectmwp_api', [$this, 'handle_ajax_request']);

        // Admin-only AJAX action used by the settings page to poll for pairing
        // completion (so the page can self-update without manual refresh).
        // No nopriv variant — only logged-in admins call this.
        add_action('wp_ajax_connectmwp_pairing_status', [$this, 'pairing_status_handler']);

        // Admin-only AJAX actions backing the "Connect ChatGPT (beta)" settings
        // card (T5): mint and revoke ChatGPT bearer tokens. Both are gated by a
        // nonce + current_user_can('manage_options') inside the handler, exactly
        // like pairing_status_handler. No nopriv variant — these are admin UX
        // only and MUST NEVER sit on the MCP traffic path.
        add_action('wp_ajax_connectmwp_cgpt_generate', [$this, 'cgpt_generate_handler']);
        add_action('wp_ajax_connectmwp_cgpt_revoke', [$this, 'cgpt_revoke_handler']);
        // Toggle the URL-embedded (path) token fallback on/off. Same nonce +
        // manage_options gating; admin UX only, never on the MCP traffic path.
        add_action('wp_ajax_connectmwp_cgpt_set_path_token', [$this, 'cgpt_set_path_token_handler']);
        // Revoke an entire connected OAuth app (one token family = access +
        // refresh + rotations). Same nonce + manage_options gating; admin UX
        // only, never on the MCP traffic path.
        add_action('wp_ajax_connectmwp_oauth_revoke', [$this, 'oauth_revoke_handler']);

        // Admin settings page hook
        add_action('admin_menu', [$this, 'add_settings_page']);

        // One-time, sentinel-guarded migration of the legacy monolithic
        // `connectmwp_keys` array into atomic per-key option rows (T039).
        // Runs on plugins_loaded so it fires on a plugin UPDATE (activation
        // hooks do not). The sentinel short-circuits after the first run, so
        // this is a single cheap get_option() on every subsequent request.
        // The lazy per-entry migration in get_key() covers the window before
        // the first plugins_loaded run on an API-only request.
        add_action('plugins_loaded', [$this, 'maybe_migrate_legacy_keys']);

        // One-time cleanup: drop the throwaway OAuth Phase-0 observational log
        // option from any install that ran the spike build. Sentinel-guarded so
        // it is a single cheap get_option() on every subsequent request.
        add_action('plugins_loaded', [$this, 'maybe_cleanup_oauth_spike_log']);

        // Intercept root /.well-known/oauth-* discovery requests BEFORE WordPress
        // routes them (WP does not natively serve /.well-known/*). Hook
        // 'parse_request' fires after WP has parsed the URL but before any
        // template/REST dispatch, which is early enough to emit a JSON document
        // and exit cleanly. Scoped tightly to /.well-known/oauth-* inside the
        // handler so it never touches acme/SSL/IndieAuth files.
        add_action('parse_request', [$this, 'oauth_wellknown_router']);

        // [OAuth Phase 1] Serve GET/POST /connectmwp-oauth/authorize as a NORMAL
        // (non-REST) front-end page via REQUEST_URI interception (same mechanism
        // as the .well-known router above — no rewrite rules, so no activation
        // flush is ever needed). This MUST NOT be a REST route: the WP REST API
        // does not establish the logged-in user from the auth cookie unless the
        // request carries a valid REST nonce (X-WP-Nonce/_wpnonce), and a
        // third-party OAuth redirect (ChatGPT -> browser -> authorize URL) cannot
        // supply that nonce. On a plain front-end request, standard cookie auth
        // establishes the admin natively, so current_user_can('manage_options')
        // works and the login loop is avoided.
        add_action('parse_request', [$this, 'oauth_authorize_router']);
    }

    // Throwaway OAuth Phase-0 observational log option. No longer written or
    // read; retained ONLY as the key that maybe_cleanup_oauth_spike_log() deletes
    // from installs that ran the spike build. Safe to drop once all installs have
    // upgraded past the cleanup release.
    const OAUTH_SPIKE_LOG_OPTION = 'connectmwp_oauth_spike_log';
    const OAUTH_SPIKE_CLEANUP_FLAG = 'connectmwp_oauth_spike_cleaned'; // one-shot cleanup sentinel

    // ========================================================================
    // [OAuth Phase 1] Real authorization endpoint constants.
    //
    // This is GENERIC OAuth 2.1 product code for ANY self-hosted WordPress site
    // and ANY spec-compliant client (ChatGPT is merely the first). Everything is
    // derived from home_url()/rest_url()/the request — never a hardcoded site or
    // client. The /oauth/{token,register} stubs from Phase 0 remain in place;
    // only GET/POST /oauth/authorize becomes real here.
    // ========================================================================

    // [OAuth Phase 1] Front-end (NON-REST) path the authorization endpoint is
    // served on, intercepted via REQUEST_URI in oauth_authorize_router(). It is a
    // clean root path (not under /wp-admin, not under /wp-json) so it works even
    // where /wp-admin or the REST API is locked down, and — critically — it is a
    // normal front-end request where WP cookie auth (is_user_logged_in /
    // current_user_can) works WITHOUT a REST nonce. This is the URL advertised as
    // authorization_endpoint in the AS metadata. No leading host; matched against
    // the request path only.
    const OAUTH_AUTHORIZE_PATH = '/connectmwp-oauth/authorize';

    // Scopes this site advertises + grants. SSOT for the authorize-time subset
    // check and the consent copy. Must stay in agreement with the
    // scopes_supported advertised in the discovery docs (oauth_discovery_urls /
    // the AS metadata) — single string scope today.
    const OAUTH_SUPPORTED_SCOPES = ['connectmwp'];

    // CIMD (client_id_metadata_document) fetch hardening.
    const OAUTH_CLIENT_ID_MAX_LEN = 2048;      // defense-in-depth: reject absurdly long client_id (a URL) before any parse/DNS/hash work
    const OAUTH_CIMD_MAX_BYTES   = 64 * 1024; // hard cap on a client metadata doc body
    const OAUTH_CIMD_TIMEOUT     = 5;          // seconds; wp_remote_get timeout for the CIMD fetch
    const OAUTH_CIMD_CACHE_TTL   = 600;        // default transient TTL (10 min) for a validated CIMD doc
    const OAUTH_CIMD_CACHE_PREFIX = 'cmwp_oauth_cimd_'; // + sha256(url) => transient name

    // Authorization-code store (own per-row + capped index DAL, mirrors the cgpt
    // token DAL). ONLY the sha256 hash of a code is ever persisted; the plaintext
    // code exists once (return of mint_oauth_code) and is never stored or logged.
    const OAUTH_CODE_OPTION_PREFIX = 'connectmwp_oauth_code_'; // + bare hex suffix => per-code option name
    const OAUTH_CODE_INDEX_OPTION  = 'connectmwp_oauth_code_index'; // map code_id => expiry (unix); legacy flat-list tolerated, self-healing
    const OAUTH_CODE_ID_PREFIX     = 'cmwp_oauthc_';           // code_id prefix (internal row id, NOT the secret)
    const OAUTH_CODE_SECRET_BYTES  = 32;                        // entropy of the auth-code secret (>= 32 random bytes)
    const OAUTH_CODE_TTL_SECONDS   = 120;                       // auth code lifetime (single-use, short)
    const MAX_OAUTH_CODES          = 200;                       // safety cap on live (mostly-expired) code rows

    // [OAuth Phase 2] Access/refresh-token store. Own per-row + capped index DAL,
    // mirroring the cgpt-token and auth-code DALs above. ONLY the sha256 hash of a
    // token is ever persisted; the plaintext exists once (return of
    // mint_oauth_tokens / rotate_oauth_refresh_token) and is never stored or
    // logged. Access tokens (cmwp_oat_) are short-lived bearer credentials the
    // resource server validates on /mcp; refresh tokens (cmwp_ort_) are
    // longer-lived and ROTATED on every use (OAuth 2.1 requires rotation for
    // public clients). The two plaintext prefixes are distinct so the resource
    // server can branch by prefix and so a refresh token can never be accepted as
    // an access token at /mcp (the resolve helpers also assert the stored `type`).
    const OAUTH_TOKEN_OPTION_PREFIX = 'connectmwp_oauth_token_'; // + bare hex suffix => per-token option name
    const OAUTH_TOKEN_INDEX_OPTION  = 'connectmwp_oauth_token_index'; // map token_id => expiry (unix); legacy flat-list tolerated, self-healing
    const OAUTH_TOKEN_ID_PREFIX     = 'cmwp_oauthtk_';          // token_id prefix (internal row id, NOT the secret)
    const OAUTH_ACCESS_TOKEN_PREFIX = 'cmwp_oat_';              // plaintext access-token prefix (also RS branch key)
    const OAUTH_REFRESH_TOKEN_PREFIX = 'cmwp_ort_';            // plaintext refresh-token prefix
    const OAUTH_TOKEN_SECRET_BYTES  = 32;                       // entropy of a token secret (>= 32 random bytes)
    const OAUTH_ACCESS_TOKEN_TTL    = 3600;                     // access-token lifetime (1 hour)
    const OAUTH_REFRESH_TOKEN_TTL   = 30 * 86400;               // refresh-token lifetime (30 days)
    const MAX_OAUTH_TOKENS          = 500;                      // safety cap on live (mostly-expired) token rows

    /**
     * Site URLs derived ONLY from home_url()/rest_url() so the advertised
     * discovery documents match whatever this install actually answers on.
     */
    private function oauth_discovery_urls() {
        $site_root = untrailingslashit(home_url());          // issuer / authorization server base
        $mcp_url   = rest_url(self::API_NAMESPACE . '/mcp');  // protected resource
        return [
            'site_root' => $site_root,
            'mcp'       => $mcp_url,
            // authorization_endpoint is the cookie-native FRONT-END page
            // (home_url path), NOT a REST route — see oauth_authorize_router /
            // the login-loop fix. The token endpoint stays REST (back-channel;
            // no browser cookie/nonce involved).
            'authorize' => home_url(self::OAUTH_AUTHORIZE_PATH),
            'token'     => rest_url(self::API_NAMESPACE . '/oauth/token'),
            'prm'       => $site_root . '/.well-known/oauth-protected-resource',
        ];
    }

    /**
     * Root /.well-known/oauth-* discovery router.
     *
     * WordPress does NOT serve /.well-known/* via the REST API or rewrite rules,
     * so OAuth discovery probes would 404 without this. We inspect the RAW
     * request URI and ONLY act on paths beginning with /.well-known/oauth- — any
     * other .well-known file (acme-challenge, SSL validation, IndieAuth, etc.)
     * passes straight through untouched. On a match we emit application/json and
     * exit immediately (before WP's main query / template). No auth, no secrets.
     */
    public function oauth_wellknown_router() {
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        if ($raw_uri === '') {
            return;
        }

        // Path only (strip query string), normalized — no decoding tricks needed
        // because we only ever compare a fixed ASCII prefix.
        $path = parse_url($raw_uri, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return;
        }

        // Tight scope: only the OAuth discovery family. Never other .well-known.
        if (strpos($path, '/.well-known/oauth-') !== 0) {
            return;
        }

        $urls = $this->oauth_discovery_urls();

        // Protected Resource Metadata (PRM). A client may probe the bare path OR a
        // sub-path that echoes the resource path; we answer both with the same doc.
        $is_prm =
            $path === '/.well-known/oauth-protected-resource'
            || strpos($path, '/.well-known/oauth-protected-resource/') === 0;

        $is_as = ($path === '/.well-known/oauth-authorization-server');

        if (!$is_prm && !$is_as) {
            // An oauth-* probe we don't model — 404 as JSON (don't hand it to
            // WP's HTML 404).
            $this->oauth_emit_json(['error' => 'not_found', 'note' => 'connectMWP — unmodeled .well-known/oauth-* path'], 404);
            return; // unreachable: emit_json exits
        }

        if ($is_prm) {
            $this->oauth_emit_json([
                'resource'                 => $urls['mcp'],
                'authorization_servers'    => [$urls['site_root']],
                'scopes_supported'         => ['connectmwp'],
                'bearer_methods_supported' => ['header'],
            ], 200);
            return; // unreachable
        }

        // Authorization Server (AS) metadata. We advertise CIMD
        // (client_id_metadata_document_supported); we do NOT advertise a
        // registration_endpoint because Dynamic Client Registration is not
        // implemented — clients identify themselves via CIMD.
        $this->oauth_emit_json([
            'issuer'                                              => $urls['site_root'],
            'authorization_endpoint'                             => $urls['authorize'],
            'token_endpoint'                                     => $urls['token'],
            'response_types_supported'                           => ['code'],
            'grant_types_supported'                              => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported'                   => ['S256'],
            'token_endpoint_auth_methods_supported'              => ['none'],
            'scopes_supported'                                   => ['connectmwp'],
            'authorization_response_iss_parameter_supported'     => true,
            'client_id_metadata_document_supported'              => true,
        ], 200);
    }

    /**
     * Emit a JSON body with explicit no-store headers and exit. Discovery docs
     * are public + non-sensitive, but no-store keeps any edge cache from pinning
     * a stale document.
     */
    private function oauth_emit_json(array $payload, int $status) {
        if (!headers_sent()) {
            status_header($status);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
        }
        echo wp_json_encode($payload);
        exit;
    }

    /**
     * One-time cleanup of the throwaway OAuth Phase-0 observational log option.
     * Sentinel-guarded via an atomic add_option so only the first worker on the
     * cleanup release performs the delete; every subsequent request is a single
     * cheap get_option() short-circuit. Runs on plugins_loaded (so it fires on a
     * plugin UPDATE, where activation hooks do not).
     */
    public function maybe_cleanup_oauth_spike_log() {
        if (!add_option(self::OAUTH_SPIKE_CLEANUP_FLAG, '1', '', 'no')) {
            return; // already cleaned (or in progress) — short-circuit
        }
        delete_option(self::OAUTH_SPIKE_LOG_OPTION);
    }

    /**
     * Attach the RFC 9728 WWW-Authenticate discovery challenge to the /mcp 401
     * response. Called from verify_token_request only on the unauthenticated 401
     * paths.
     *
     * A permission_callback returns a WP_Error that WP turns into the HTTP
     * response LATER, so setting a header here directly would be lost. Instead we
     * register a one-shot rest_post_dispatch filter that injects the header onto
     * the outgoing 401 response object. The header points the client at our PRM
     * document, which kicks off discovery.
     */
    private function oauth_emit_www_authenticate() {
        if ($this->oauth_www_auth_hooked) {
            return; // guard: permission_callback can fire twice per request
        }
        $this->oauth_www_auth_hooked = true;

        $urls  = $this->oauth_discovery_urls();
        $value = sprintf(
            'Bearer resource_metadata="%s", scope="connectmwp"',
            $urls['prm']
        );

        $namespace = self::API_NAMESPACE;
        add_filter('rest_post_dispatch', function ($response, $server, $request) use ($value, $namespace) {
            // Only stamp genuine 401 responses (the unauthenticated path); never a 200.
            if (!($response instanceof WP_REST_Response) || (int) $response->get_status() !== 401) {
                return $response;
            }
            // Scope the RFC 9728 discovery challenge to the /mcp route ONLY (and its
            // /mcp/<token> variant). The challenge advertises bearer-token OAuth, which
            // is meaningless on the signature-authenticated endpoints (/enroll,
            // /whoami, /posts, ...) — stamping it there would be a misleading header on
            // an unrelated 401. We match the matched route, not the raw path, so query
            // strings / trailing slashes don't matter.
            if (!($request instanceof WP_REST_Request)) {
                return $response;
            }
            $route = (string) $request->get_route();
            $is_mcp = ($route === '/' . $namespace . '/mcp')
                || (strpos($route, '/' . $namespace . '/mcp/') === 0);
            if ($is_mcp) {
                $response->header('WWW-Authenticate', $value);
            }
            return $response;
        }, 10, 3);
    }

    /** One-shot guard so the WWW-Authenticate filter is added once. */
    private $oauth_www_auth_hooked = false;

    // ========================================================================
    // [OAuth Phase 1] Real GET/POST authorization endpoint, served at
    // OAUTH_AUTHORIZE_PATH as a cookie-native FRONT-END page (NOT a REST route).
    //
    // Validates the request fail-closed in a strict order (HTTPS -> response_type
    // -> admin gate -> CIMD client -> EXACT redirect_uri match -> PKCE S256 ->
    // resource == this /mcp -> scope subset), renders a consent screen with a
    // bound-user picker, and on approval mints a single-use, short-TTL, hashed
    // authorization code bound to the PKCE challenge. Phase 2's /oauth/token will
    // consume that code.
    //
    // Served front-end (via oauth_authorize_router on parse_request) rather than
    // REST precisely so standard WP cookie auth establishes the logged-in admin
    // WITHOUT a REST nonce — a third-party OAuth redirect cannot supply one, and a
    // REST route's current_user_can() would always be false, causing an infinite
    // wp-login loop. The auth here is the WP admin LOGIN SESSION + a nonce on the
    // POST, not an Ed25519 signature or bearer token. It NEVER touches
    // verify_request_signature / verify_token_request / dispatch_action. The
    // endpoint always renders HTML or issues a 302 redirect and exit()s.
    // ========================================================================

    /**
     * [OAuth Phase 1] Front-end router for the authorization endpoint.
     *
     * Fires on parse_request (same lifecycle stage as the .well-known router).
     * At this point WordPress has already loaded the auth cookie, so the current
     * user IS established and current_user_can('manage_options') works WITHOUT a
     * REST nonce — which is the entire fix for the login loop. We match the exact
     * OAUTH_AUTHORIZE_PATH (tolerant of a trailing slash + query string, but NOT
     * a loose prefix), then dispatch into oauth_authorize_handler() for both GET
     * and POST. The handler always renders HTML or 302-redirects and exit()s.
     */
    public function oauth_authorize_router() {
        $raw_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        if ($raw_uri === '') {
            return;
        }

        $path = parse_url($raw_uri, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return;
        }
        // Exact match, tolerant only of a single trailing slash. NOT a prefix match
        // (so e.g. /connectmwp-oauth/authorize-evil or /connectmwp-oauth/authorize/x
        // do NOT match).
        $normalized = untrailingslashit($path);
        if ($normalized !== self::OAUTH_AUTHORIZE_PATH) {
            return;
        }

        // Dispatch into the shared handler. Pass null — the handler reads request
        // params from $_GET/$_POST and the method from $_SERVER['REQUEST_METHOD'].
        $this->oauth_authorize_handler(null);
        exit; // defensive: the handler always exit()s, but never fall through to WP.
    }

    /**
     * [OAuth Phase 1] GET/POST authorization endpoint, served at
     * OAUTH_AUTHORIZE_PATH as a NORMAL front-end page (see oauth_authorize_router)
     * — NOT a REST route. It is served front-end specifically so standard WP
     * cookie authentication establishes the logged-in admin WITHOUT a REST nonce
     * (a third-party OAuth redirect cannot supply one), which fixes the login
     * loop. This method performs ALL of its own auth (admin login session + WP
     * nonce on the POST). Output is always an HTML page or a 302 redirect followed
     * by exit().
     *
     * Reads request params from $_GET/$_POST (sanitized in
     * oauth_collect_authorize_params); the $request argument is unused and always
     * null when called from the front-end router.
     */
    public function oauth_authorize_handler($request = null) {
        $method = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper((string) wp_unslash($_SERVER['REQUEST_METHOD']))
            : 'GET';

        // (1) HTTPS required. Authorization codes and login sessions must never
        // cross plaintext. Reuse the same transport check the rest of the plugin
        // relies on (is_ssl plus forwarded-proto awareness via request_is_https).
        if (!$this->oauth_request_is_https()) {
            $this->oauth_render_error_page(
                __('Insecure connection', 'connectmwp'),
                __('This authorization endpoint requires HTTPS. Your connection is not secure, so the request was refused.', 'connectmwp'),
                400
            );
        }

        // Gather the OAuth params. On GET they live in the query string; on POST
        // (the consent submission) we echo them back as hidden form fields, so
        // read both via the merged param bag. We never trust POSTed params to
        // weaken anything — every check below re-runs against them.
        $params = $this->oauth_collect_authorize_params($request);

        // (2) response_type MUST be exactly "code".
        if ($params['response_type'] !== 'code') {
            // We cannot yet trust a redirect_uri (CIMD not resolved), so render an
            // error page rather than redirecting.
            $this->oauth_render_error_page(
                __('Unsupported response type', 'connectmwp'),
                __('This server only supports the authorization-code flow (response_type=code).', 'connectmwp'),
                400
            );
        }

        // (3) Admin gate — MUST run BEFORE the outbound CIMD fetch (step 4). If we
        // resolved the client first, any unauthenticated internet caller could make
        // this server fetch an arbitrary https URL (the client_id) — an
        // unauthenticated SSRF trigger. By gating on a logged-in admin here, the
        // outbound fetch is only ever reachable by an authenticated site admin.
        // Both branches below use error PAGES / login redirect (NOT an OAuth
        // redirect): no trusted redirect_uri exists yet.
        if (!is_user_logged_in()) {
            // Bounce through wp-login, returning to THIS authorize URL (all params
            // preserved) so the flow resumes after login. wp_login_url escapes the
            // redirect target for us.
            $self_url = $this->oauth_self_authorize_url($params);
            wp_safe_redirect(wp_login_url($self_url));
            exit;
        }
        if (!current_user_can('manage_options')) {
            // Logged in but not an admin — clear denial, no login loop.
            $this->oauth_render_error_page(
                __('Administrator required', 'connectmwp'),
                __('Only site administrators can authorize a connector for this site. Please sign in with an administrator account and try again.', 'connectmwp'),
                403
            );
        }

        // (4) Resolve the client via its CIMD document (SSRF-guarded fetch). Only
        // reachable by an authenticated admin (gated at step 3). On ANY failure we
        // render an ERROR PAGE — we have no trusted redirect_uri to send the error
        // to yet.
        $client = $this->resolve_oauth_client($params['client_id']);
        if (is_wp_error($client)) {
            $this->oauth_render_error_page(
                __('Unrecognized application', 'connectmwp'),
                sprintf(
                    /* translators: %s: reason the client could not be validated */
                    __('The requesting application could not be verified: %s', 'connectmwp'),
                    $client->get_error_message()
                ),
                400
            );
        }

        // (5) redirect_uri MUST be an EXACT string match to one of the CIMD doc's
        // registered redirect_uris. This is the open-redirect guard: only AFTER it
        // passes may any subsequent error be delivered BY redirecting to this URI.
        if ($params['redirect_uri'] === '' || !$this->oauth_redirect_uri_registered($params['redirect_uri'], $client['redirect_uris'])) {
            $this->oauth_render_error_page(
                __('Invalid redirect URI', 'connectmwp'),
                __('The redirect address supplied does not match any address registered by this application. For your safety, the request was refused.', 'connectmwp'),
                400
            );
        }
        // From here on, $params['redirect_uri'] is TRUSTED and errors may redirect.

        // (6) PKCE: code_challenge present, well-formed, AND method exactly S256.
        // Reject plain, missing, or malformed/over-long challenges — downgrade and
        // junk-input protection.
        if ($params['code_challenge'] === ''
            || $params['code_challenge_method'] !== 'S256'
            || !preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $params['code_challenge'])) {
            $this->oauth_redirect_error(
                $params['redirect_uri'],
                'invalid_request',
                __('PKCE with a well-formed code_challenge and code_challenge_method=S256 is required.', 'connectmwp'),
                $params['state']
            );
        }

        // (7) resource MUST equal this site's canonical /mcp URI (RFC 8707).
        if (!$this->oauth_resource_matches($params['resource'])) {
            $this->oauth_redirect_error(
                $params['redirect_uri'],
                'invalid_target',
                __('The requested resource does not match this server.', 'connectmwp'),
                $params['state']
            );
        }

        // (8) scope: every requested scope must be in the advertised set. An empty
        // scope defaults to the full advertised set (single scope today).
        $requested_scopes = $this->oauth_parse_scope($params['scope']);
        foreach ($requested_scopes as $s) {
            if (!in_array($s, self::OAUTH_SUPPORTED_SCOPES, true)) {
                $this->oauth_redirect_error(
                    $params['redirect_uri'],
                    'invalid_scope',
                    __('One or more requested scopes are not supported by this server.', 'connectmwp'),
                    $params['state']
                );
            }
        }
        $granted_scope = implode(' ', $requested_scopes);

        // ---- POST: consent submission (approve / deny) ----
        if ($method === 'POST') {
            // CSRF: verify the consent nonce. wp_verify_nonce is the right tool here
            // (REST routes don't auto-enforce the cookie nonce on a public
            // permission_callback). Re-check manage_options (already done above).
            $nonce = isset($_POST['connectmwp_oauth_nonce']) ? sanitize_text_field(wp_unslash($_POST['connectmwp_oauth_nonce'])) : '';
            if (!wp_verify_nonce($nonce, 'connectmwp_oauth_consent')) {
                $this->oauth_render_error_page(
                    __('Session expired', 'connectmwp'),
                    __('Your authorization session expired or was invalid. Please start the connection again from your application.', 'connectmwp'),
                    400
                );
            }
            if (!current_user_can('manage_options')) {
                $this->oauth_render_error_page(
                    __('Administrator required', 'connectmwp'),
                    __('Only site administrators can authorize a connector for this site.', 'connectmwp'),
                    403
                );
            }

            $decision = isset($_POST['connectmwp_oauth_decision']) ? sanitize_text_field(wp_unslash($_POST['connectmwp_oauth_decision'])) : '';

            if ($decision === 'approve') {
                // Determine the bound user from the picker. Must be an eligible
                // (edit_posts-capable) user; fall back to the current admin if the
                // submitted value is missing or ineligible (never silently grant a
                // worse-or-unexpected binding — re-validate against capability).
                $bound_user_id = isset($_POST['connectmwp_oauth_bound_user']) ? intval($_POST['connectmwp_oauth_bound_user']) : 0;
                if ($bound_user_id <= 0 || !user_can($bound_user_id, 'edit_posts')) {
                    $current_id = get_current_user_id();
                    if (user_can($current_id, 'edit_posts')) {
                        $bound_user_id = $current_id;
                    } else {
                        // Pathological: an admin with manage_options but not
                        // edit_posts (custom role). Refuse rather than bind to a
                        // user who can't perform the granted actions.
                        $this->oauth_render_error_page(
                            __('No eligible user', 'connectmwp'),
                            __('No content-capable user was selected for this connection.', 'connectmwp'),
                            400
                        );
                    }
                }

                // (11) Mint a single-use, short-TTL, hashed auth code bound to the
                // PKCE challenge, the validated client_id + redirect_uri, the
                // resource, the granted scope, and the selected bound user.
                $code = $this->mint_oauth_code([
                    'client_id'             => $params['client_id'],
                    'redirect_uri'          => $params['redirect_uri'],
                    'code_challenge'        => $params['code_challenge'],
                    'code_challenge_method' => 'S256',
                    'resource'              => $this->oauth_canonical_mcp_uri(),
                    'bound_user_id'         => $bound_user_id,
                    'scope'                 => $granted_scope,
                ]);

                if (is_wp_error($code) || !is_string($code) || $code === '') {
                    // The redirect_uri is validated by this point, so deliver the
                    // failure BY redirecting. A capacity rejection (the
                    // MAX_OAUTH_CODES cap) is transient, so signal
                    // temporarily_unavailable; everything else is server_error.
                    $is_capacity = is_wp_error($code) && $code->get_error_code() === 'cmwp_oauth_code_capacity';
                    $this->oauth_redirect_error(
                        $params['redirect_uri'],
                        $is_capacity ? 'temporarily_unavailable' : 'server_error',
                        $is_capacity
                            ? __('The server is briefly at capacity for pending authorizations. Please try again shortly.', 'connectmwp')
                            : __('Could not issue an authorization code. Please try again.', 'connectmwp'),
                        $params['state']
                    );
                }

                // Success redirect: ?code=...&state=...&iss=<root>
                $sep = (strpos($params['redirect_uri'], '?') === false) ? '?' : '&';
                $url = $params['redirect_uri'] . $sep
                    . 'code=' . rawurlencode($code)
                    . ($params['state'] !== '' ? '&state=' . rawurlencode($params['state']) : '')
                    . '&iss=' . rawurlencode($this->oauth_issuer());
                $this->oauth_redirect_raw($url);
            }

            // Deny (or any non-approve decision): access_denied back to the client.
            $this->oauth_redirect_error(
                $params['redirect_uri'],
                'access_denied',
                __('The administrator declined to authorize this connection.', 'connectmwp'),
                $params['state']
            );
        }

        // ---- GET: render the consent screen ----
        $this->oauth_render_consent_screen($client, $params, $requested_scopes);
    }

    /**
     * [OAuth Phase 1] Collect + sanitize the authorize params from the raw
     * superglobals, reading the query bag on GET and (for POST consent) the echoed
     * hidden fields. The endpoint is served as a normal front-end page (not REST),
     * so there is no WP_REST_Request — params come straight from $_GET/$_POST.
     * Returns a fixed-shape array of strings. No secrets are logged.
     */
    private function oauth_collect_authorize_params($request = null) {
        $get = function ($key) {
            // Prefer POST (the consent submission echoes every param as a hidden
            // field) over GET, then unslash. Every value is re-validated downstream.
            if (isset($_POST[$key]) && is_scalar($_POST[$key])) {
                return (string) wp_unslash($_POST[$key]);
            }
            if (isset($_GET[$key]) && is_scalar($_GET[$key])) {
                return (string) wp_unslash($_GET[$key]);
            }
            return '';
        };

        return [
            'response_type'         => trim($get('response_type')),
            'client_id'             => trim($get('client_id')),
            'redirect_uri'          => trim($get('redirect_uri')),
            'scope'                 => trim($get('scope')),
            'state'                 => substr($get('state'), 0, 2048), // opaque; preserved verbatim but hard-capped at 2048 chars to bound echo size
            'code_challenge'        => trim($get('code_challenge')),
            'code_challenge_method' => trim($get('code_challenge_method')),
            'resource'              => trim($get('resource')),
        ];
    }

    /**
     * [OAuth Phase 1] Whether the inbound request arrived over HTTPS, accounting
     * for a reverse proxy that terminates TLS and forwards X-Forwarded-Proto
     * (common on managed hosts). Mirrors the plugin's transport expectation.
     */
    private function oauth_request_is_https() {
        return $this->is_https_request();
    }

    /**
     * SSOT transport gate: whether the inbound request arrived over HTTPS.
     *
     * Every auth gate in the plugin (the two OAuth front-end handlers, the bearer
     * token verifier, and the Ed25519 signature verifier) MUST agree on this, or
     * a reverse-proxy site can half-work: OAuth authorize/token succeed but the
     * resulting access token then fails an inconsistent HTTPS check at /mcp.
     *
     * PURELY ADDITIVE for non-proxy sites: is_behind_trusted_proxy() defaults OFF,
     * so when the admin has NOT opted into proxy trust the X-Forwarded-Proto branch
     * is unreachable and this returns exactly what is_ssl() returns. The forwarded
     * header is honored ONLY when is_behind_trusted_proxy() is true (same discipline
     * as get_client_ip) — otherwise a client could spoof the header to defeat the gate.
     */
    private function is_https_request(): bool {
        if (is_ssl()) {
            return true;
        }
        if ($this->is_behind_trusted_proxy()
            && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
            && strtolower(trim((string) wp_unslash($_SERVER['HTTP_X_FORWARDED_PROTO']))) === 'https') {
            return true;
        }
        return false;
    }

    /** [OAuth Phase 1] Issuer = site root (scheme+host[+port]), no trailing slash. */
    private function oauth_issuer() {
        return untrailingslashit(home_url());
    }

    /** [OAuth Phase 1] Canonical protected-resource URI for this site's /mcp. */
    private function oauth_canonical_mcp_uri() {
        return rest_url(self::API_NAMESPACE . '/mcp');
    }

    /**
     * [OAuth Phase 2] SSOT normalization for RFC 8707 resource-indicator
     * comparison. Returns a canonical comparison string, or NULL if the input is
     * not a usable bare URI. Normalization: trim, drop a trailing slash,
     * lowercase scheme + host (path stays case-exact), preserve port. RFC 8707:
     * the resource indicator must be a bare URI — a query string or fragment is
     * rejected (returns NULL) rather than silently stripped. Both the canonical
     * /mcp check (oauth_resource_matches) and the grant cross-check
     * (oauth_token_grant_authorization_code, I-1) MUST go through this so the two
     * comparisons can never drift.
     *
     * @return string|null Canonical compare form, or null for a non-comparable
     *                     value (empty, non-string, or carrying query/fragment).
     */
    private function oauth_normalize_resource_for_compare($resource) {
        if (!is_string($resource) || $resource === '') {
            return null;
        }
        if (strpos($resource, '?') !== false || strpos($resource, '#') !== false) {
            return null;
        }
        $u = untrailingslashit(trim($resource));
        $p = wp_parse_url($u);
        if (!is_array($p) || empty($p['host'])) {
            return strtolower($u);
        }
        $scheme = isset($p['scheme']) ? strtolower($p['scheme']) : 'https';
        $host   = strtolower($p['host']);
        $port   = isset($p['port']) ? ':' . $p['port'] : '';
        $path   = isset($p['path']) ? $p['path'] : '';
        return $scheme . '://' . $host . $port . $path;
    }

    /**
     * [OAuth Phase 1] Canonical comparison of a requested `resource` against this
     * site's /mcp URI. Normalizes a trailing slash and is scheme/host
     * case-insensitive (host only) so trivial formatting differences don't cause
     * a false invalid_target, while the path stays exact. Shares
     * oauth_normalize_resource_for_compare with the grant cross-check (I-1).
     */
    private function oauth_resource_matches($resource) {
        $candidate = $this->oauth_normalize_resource_for_compare($resource);
        if ($candidate === null) {
            return false;
        }
        $canonical = $this->oauth_normalize_resource_for_compare($this->oauth_canonical_mcp_uri());
        if ($canonical === null) {
            return false;
        }
        return hash_equals($canonical, $candidate);
    }

    /**
     * [OAuth Phase 1] Parse an OAuth scope string into a unique list. An empty
     * scope defaults to the full advertised set (single scope today).
     */
    private function oauth_parse_scope($scope) {
        // INVARIANT (Minor 5): an empty/absent scope is treated as the full
        // advertised set (`connectmwp`) EVERYWHERE — at mint, at refresh no-widen
        // comparison, and at the /mcp scope gate. Because both sides of every
        // subset check pass through this same expansion, an empty stored scope and
        // an empty requested scope both normalize to ['connectmwp'], so the
        // no-widen guard can never be fooled by an empty string.
        $scope = is_string($scope) ? trim($scope) : '';
        if ($scope === '') {
            return self::OAUTH_SUPPORTED_SCOPES;
        }
        $parts = preg_split('/\s+/', $scope);
        $parts = array_values(array_unique(array_filter(array_map('strval', $parts), function ($s) {
            return $s !== '';
        })));
        return $parts;
    }

    /**
     * [OAuth Phase 1] EXACT-match a presented redirect_uri against the CIMD doc's
     * registered redirect_uris. No normalization, no prefix match — byte-for-byte
     * equality (constant-time) against each registered entry. This is the core
     * open-redirect defense.
     */
    private function oauth_redirect_uri_registered($redirect_uri, array $registered) {
        foreach ($registered as $entry) {
            if (is_string($entry) && hash_equals($entry, $redirect_uri)) {
                return true;
            }
        }
        return false;
    }

    /**
     * [OAuth Phase 1] Rebuild this authorize endpoint's own URL with all OAuth
     * params, used as the post-login return target. Built from
     * home_url(OAUTH_AUTHORIZE_PATH) — the front-end (cookie-native) authorize
     * URL — so that after wp-login redirects back here, standard cookie auth
     * works WITHOUT a REST nonce (this is the login-loop fix).
     */
    private function oauth_self_authorize_url(array $params) {
        $base = home_url(self::OAUTH_AUTHORIZE_PATH);
        $query = [
            'response_type'         => $params['response_type'],
            'client_id'             => $params['client_id'],
            'redirect_uri'          => $params['redirect_uri'],
            'scope'                 => $params['scope'],
            'state'                 => $params['state'],
            'code_challenge'        => $params['code_challenge'],
            'code_challenge_method' => $params['code_challenge_method'],
            'resource'              => $params['resource'],
        ];
        // add_query_arg() URL-encodes the values itself; pass them raw to avoid
        // double-encoding. Empty values are dropped to keep the URL tidy (they
        // re-default identically on the next pass).
        $query = array_filter($query, function ($v) { return $v !== ''; });
        return add_query_arg($query, $base);
    }

    /**
     * [OAuth Phase 1] Redirect back to a (previously VALIDATED) redirect_uri with
     * a standard OAuth error, the echoed state, and the iss parameter. Caller
     * MUST have already confirmed $redirect_uri is registered. exit()s.
     */
    private function oauth_redirect_error($redirect_uri, $error, $description, $state) {
        $sep = (strpos($redirect_uri, '?') === false) ? '?' : '&';
        $url = $redirect_uri . $sep
            . 'error=' . rawurlencode($error)
            . '&error_description=' . rawurlencode($description)
            . ($state !== '' ? '&state=' . rawurlencode($state) : '')
            . '&iss=' . rawurlencode($this->oauth_issuer());
        $this->oauth_redirect_raw($url);
    }

    /**
     * [OAuth Phase 1] Emit a 302 to an absolute external URL and exit. We do NOT
     * use wp_safe_redirect here because the target is an OAuth client's
     * redirect_uri (a foreign host) that we have ALREADY validated by exact match
     * against the CIMD-registered list — wp_safe_redirect's allowed-host filter
     * would otherwise rewrite it to the admin dashboard. The exact-match check
     * upstream is the safety boundary.
     */
    private function oauth_redirect_raw($url) {
        if (!headers_sent()) {
            status_header(302);
            header('Location: ' . $url, true, 302);
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            // Don't leak the authorize URL's params (code/state/etc.) to the
            // destination via the Referer header.
            header('Referrer-Policy: no-referrer');
        }
        exit;
    }

    // ----------------------- [OAuth Phase 1] SSRF guard --------------------

    /**
     * [OAuth Phase 1] SSRF-hardened HTTPS GET, used ONLY for fetching a client's
     * CIMD (client_id metadata) document. Defenses:
     *   - require https:// (no http, no file://, no other schemes);
     *   - resolve the host and REJECT if ANY resolved address is private /
     *     loopback / link-local / unique-local / 0.0.0.0/8 / IPv4-mapped-IPv6;
     *   - redirection => 0 (never follow a redirect, which could bounce to an
     *     internal address);
     *   - small timeout + response-size cap (limit_response_size).
     *
     * DNS-rebinding TOCTOU CLOSED (T084): we resolve + screen the host here, then
     * pin the screened addresses into the actual fetch via cURL's CURLOPT_RESOLVE
     * (host:port => screened IPs), so the transport connects to an already-
     * validated address instead of performing a second, attacker-controllable DNS
     * resolution at socket-open time. The URL host is unchanged, so SNI + TLS
     * certificate verification still target the real hostname. On the rare host
     * with no cURL transport the pin action never fires and we fall back to the
     * screen-only behavior (still protected by redirection=>0 + scheme/size caps).
     *
     * @param string $url
     * @param int    $max_bytes
     * @param int    $timeout
     * @return string|WP_Error Body on success, WP_Error on any failure/violation.
     */
    private function oauth_safe_http_get($url, $max_bytes, $timeout) {
        if (!is_string($url) || $url === '') {
            return new WP_Error('cmwp_oauth_ssrf', __('Empty URL.', 'connectmwp'));
        }

        $parts = wp_parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return new WP_Error('cmwp_oauth_ssrf', __('Malformed URL.', 'connectmwp'));
        }
        if (strtolower($parts['scheme']) !== 'https') {
            return new WP_Error('cmwp_oauth_ssrf', __('Only https URLs are allowed.', 'connectmwp'));
        }

        $host = $parts['host'];

        // If the host is a literal IP, screen it directly. Otherwise resolve it
        // (A + AAAA) and screen every address.
        $ips = [];
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips[] = $host;
        } else {
            // IPv4 (and CNAME-followed) addresses.
            $v4 = gethostbynamel($host);
            if (is_array($v4)) {
                $ips = array_merge($ips, $v4);
            }
            // IPv6 addresses, if the resolver is available.
            if (function_exists('dns_get_record')) {
                $aaaa = @dns_get_record($host, DNS_AAAA);
                if (is_array($aaaa)) {
                    foreach ($aaaa as $rec) {
                        if (!empty($rec['ipv6'])) {
                            $ips[] = $rec['ipv6'];
                        }
                    }
                }
            }
            if (empty($ips)) {
                return new WP_Error('cmwp_oauth_ssrf', __('Could not resolve the application host.', 'connectmwp'));
            }
        }

        foreach ($ips as $ip) {
            if (!$this->oauth_ip_is_public($ip)) {
                return new WP_Error('cmwp_oauth_ssrf', __('The application host resolves to a non-public address and was refused.', 'connectmwp'));
            }
        }

        // DNS-REBINDING CLOSE (T084): pin the screened addresses into the fetch.
        // Every resolved IP passed oauth_ip_is_public() above; pin the host to
        // that exact set via CURLOPT_RESOLVE so cURL connects to a validated
        // address rather than re-resolving the host (which a hostile DNS server
        // could rebind to a private/loopback IP between our screen and the socket
        // open). Comma-listing all screened IPs preserves cURL's normal failover.
        // The hook is scoped to THIS request and removed in finally{}.
        $pinned_ips = implode(',', $ips);
        $pin_port   = !empty($parts['port']) ? (int) $parts['port'] : 443;
        $pin_curl   = static function ($handle) use ($host, $pin_port, $pinned_ips) {
            if (function_exists('curl_setopt') && defined('CURLOPT_RESOLVE')) {
                curl_setopt($handle, CURLOPT_RESOLVE, ["{$host}:{$pin_port}:{$pinned_ips}"]);
            }
        };
        add_action('http_api_curl', $pin_curl, 10, 1);
        try {
            $response = wp_remote_get($url, [
                'timeout'             => intval($timeout),
                'redirection'         => 0,                 // never follow redirects
                'limit_response_size' => intval($max_bytes),
                'sslverify'           => true,
                'headers'             => ['Accept' => 'application/json'],
                'user-agent'          => 'connectMWP/' . self::version() . ' (+OAuth CIMD fetch)',
            ]);
        } finally {
            remove_action('http_api_curl', $pin_curl, 10);
        }

        if (is_wp_error($response)) {
            return new WP_Error('cmwp_oauth_fetch', __('Could not reach the application metadata document.', 'connectmwp'));
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        if ($status !== 200) {
            return new WP_Error('cmwp_oauth_fetch', sprintf(
                /* translators: %d: HTTP status code */
                __('The application metadata document returned HTTP %d.', 'connectmwp'),
                $status
            ));
        }

        $body = wp_remote_retrieve_body($response);
        if (!is_string($body) || $body === '') {
            return new WP_Error('cmwp_oauth_fetch', __('The application metadata document was empty.', 'connectmwp'));
        }
        if (strlen($body) > $max_bytes) {
            return new WP_Error('cmwp_oauth_fetch', __('The application metadata document is too large.', 'connectmwp'));
        }

        return $body;
    }

    /**
     * [OAuth Phase 1] True only if $ip is a routable, public address. Rejects
     * private (RFC1918 / ULA), loopback, link-local, reserved ranges, 0.0.0.0/8,
     * and IPv4-mapped-IPv6 (::ffff:a.b.c.d) so an attacker can't tunnel a private
     * IPv4 through an IPv6 literal.
     */
    private function oauth_ip_is_public($ip) {
        $ip = trim((string) $ip);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1 etc.) and re-screen as IPv4.
        if (stripos($ip, '::ffff:') === 0) {
            $mapped = substr($ip, 7);
            if (filter_var($mapped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip = $mapped;
            } else {
                return false; // unusual mapped form — refuse
            }
        }

        // Reject explicit 0.0.0.0/8 (filter_var's NO_RES_RANGE covers much of
        // this, but be explicit about the "this host" range).
        if (strpos($ip, '0.') === 0) {
            return false;
        }

        // Core screen: must be a valid IP that is NOT in a private or reserved
        // range. NO_PRIV_RANGE covers RFC1918 + ULA (fc00::/7); NO_RES_RANGE
        // covers loopback, link-local (169.254/16, fe80::/10), 0.0.0.0/8,
        // multicast, and other reserved blocks.
        $ok = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
        return $ok !== false;
    }

    // ------------------- [OAuth Phase 1] CIMD client resolution ------------

    /**
     * [OAuth Phase 1] Resolve + validate a CIMD client_id (which is itself an
     * https URL pointing at a JSON client-metadata document). Returns a minimal,
     * trusted descriptor or a WP_Error.
     *
     * Validation:
     *   - client_id MUST be an https:// URL WITH a path component;
     *   - the document is fetched via the SSRF-guarded GET;
     *   - it MUST be JSON with client_id, client_name, redirect_uris[] present;
     *   - the doc's own client_id MUST equal the requested client_id EXACTLY
     *     (including any query string) — prevents a doc claiming to be a
     *     different client;
     *   - redirect_uris must be a non-empty list of strings.
     * Validated docs are cached briefly in a transient keyed by sha256(url).
     *
     * @param string $client_id
     * @return array{client_id:string,client_name:string,redirect_uris:array}|WP_Error
     */
    private function resolve_oauth_client($client_id) {
        if (!is_string($client_id) || $client_id === '') {
            return new WP_Error('cmwp_oauth_client', __('Missing client_id.', 'connectmwp'));
        }

        // Defense-in-depth: a client_id is a URL to a metadata document. Reject an
        // absurdly long value BEFORE any wp_parse_url / DNS (gethostbynamel) / hash
        // work so a hostile string can't drive unnecessary resolution/parsing cost.
        // Same "unrecognized application" error path as a malformed client_id.
        if (strlen($client_id) > self::OAUTH_CLIENT_ID_MAX_LEN) {
            return new WP_Error('cmwp_oauth_client', __('client_id must be an https URL with a path to a metadata document.', 'connectmwp'));
        }

        $parts = wp_parse_url($client_id);
        if (!is_array($parts)
            || empty($parts['scheme']) || strtolower($parts['scheme']) !== 'https'
            || empty($parts['host'])
            || empty($parts['path']) || $parts['path'] === '/') {
            return new WP_Error('cmwp_oauth_client', __('client_id must be an https URL with a path to a metadata document.', 'connectmwp'));
        }

        // Cache lookup (validated docs only).
        $cache_key = self::OAUTH_CIMD_CACHE_PREFIX . hash('sha256', $client_id);
        $cached = get_transient($cache_key);
        if (is_array($cached) && isset($cached['client_id'], $cached['client_name'], $cached['redirect_uris'])) {
            return $cached;
        }

        $body = $this->oauth_safe_http_get($client_id, self::OAUTH_CIMD_MAX_BYTES, self::OAUTH_CIMD_TIMEOUT);
        if (is_wp_error($body)) {
            return $body;
        }

        $doc = json_decode($body, true);
        if (!is_array($doc)) {
            return new WP_Error('cmwp_oauth_client', __('The application metadata document is not valid JSON.', 'connectmwp'));
        }

        $doc_client_id = isset($doc['client_id']) && is_string($doc['client_id']) ? $doc['client_id'] : '';
        $client_name   = isset($doc['client_name']) && is_string($doc['client_name']) ? $doc['client_name'] : '';
        $redirect_uris = isset($doc['redirect_uris']) && is_array($doc['redirect_uris']) ? $doc['redirect_uris'] : null;

        if ($doc_client_id === '' || $client_name === '' || $redirect_uris === null) {
            return new WP_Error('cmwp_oauth_client', __('The application metadata document is missing required fields.', 'connectmwp'));
        }

        // The document's client_id MUST equal the requested client_id EXACTLY.
        if (!hash_equals($client_id, $doc_client_id)) {
            return new WP_Error('cmwp_oauth_client', __('The application metadata document does not match the requested client_id.', 'connectmwp'));
        }

        // redirect_uris: keep only well-formed, non-plaintext entries; require at
        // least one. Accept https:// and custom mobile/native schemes (e.g.
        // myapp://...); REJECT plaintext http:// — an authorization code must never
        // be delivered over cleartext. A loopback http URI is no exception here:
        // Phase 1 has no native-app loopback story, so we keep the rule strict.
        $clean_uris = [];
        foreach ($redirect_uris as $u) {
            if (!is_string($u) || $u === '') {
                continue;
            }
            $scheme = strtolower((string) wp_parse_url($u, PHP_URL_SCHEME));
            if ($scheme === 'http') {
                continue; // plaintext — never accept
            }
            $clean_uris[] = $u;
        }
        if (empty($clean_uris)) {
            return new WP_Error('cmwp_oauth_client', __('The application registered no usable (non-plaintext) redirect URIs.', 'connectmwp'));
        }

        $result = [
            'client_id'     => $doc_client_id,
            'client_name'   => $client_name,
            'redirect_uris' => $clean_uris,
        ];

        set_transient($cache_key, $result, self::OAUTH_CIMD_CACHE_TTL);
        return $result;
    }

    // ------------------ [OAuth Phase 1] consent + error pages --------------

    /**
     * [OAuth Phase 1] Render a standalone, full-page consent screen and exit.
     * Deliberately a self-contained HTML document (NOT wrapped via wp_iframe or
     * the admin chrome) so third-party admin/plugin markup cannot interfere — the
     * same standalone approach the pairing screen uses. Everything echoed is
     * escaped. A WP nonce CSRF-protects the Approve/Deny POST back to this same
     * endpoint.
     *
     * @param array $client           Validated CIMD descriptor.
     * @param array $params           Collected authorize params (already validated).
     * @param array $requested_scopes List of requested scope strings.
     */
    private function oauth_render_consent_screen(array $client, array $params, array $requested_scopes) {
        $current_id = get_current_user_id();
        $eligible = get_users([
            'capability' => 'edit_posts',
            'orderby'    => 'display_name',
            'order'      => 'ASC',
            'number'     => 200,
        ]);

        $site_name = html_entity_decode(get_bloginfo('name'), ENT_QUOTES, 'UTF-8');
        $site_url  = home_url();
        $redirect_host = '';
        $redirect_origin = '';
        $rp = wp_parse_url($params['redirect_uri']);
        if (is_array($rp) && !empty($rp['host'])) {
            $redirect_host = $rp['host'];
            if (!empty($rp['scheme'])) {
                // scheme://host[:port] of the (already CIMD-exact-matched, trusted)
                // client redirect_uri — needed in the CSP form-action below.
                $redirect_origin = $rp['scheme'] . '://' . $rp['host'] . (isset($rp['port']) ? ':' . intval($rp['port']) : '');
            }
        }

        // Plain-English scope description.
        $scope_desc = $this->oauth_scope_plain_english($requested_scopes);

        $nonce       = wp_create_nonce('connectmwp_oauth_consent');
        // POST back to the SAME front-end authorize URL (not REST), so cookie auth
        // + the WP nonce authorize the consent submission.
        $form_action = home_url(self::OAUTH_AUTHORIZE_PATH);

        if (!headers_sent()) {
            status_header(200);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('X-Frame-Options: DENY'); // never allow this consent UI to be framed
            // Self-contained page: no scripts, only inline styles. form-action must
            // allow BOTH 'self' (the consent POST target) AND the validated client
            // redirect_uri origin — CSP form-action ALSO governs the 302 that
            // FOLLOWS the form POST, so without the client origin the browser
            // silently blocks the post-approval redirect to the client and the
            // consent screen appears to "do nothing". redirect_uri is already
            // exact-matched against the CIMD doc by this point, so its origin is trusted.
            $csp_form_action = "'self'" . ($redirect_origin !== '' ? ' ' . $redirect_origin : '');
            header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action " . $csp_form_action . ";");
            header('X-Content-Type-Options: nosniff');
        }
        ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?php echo esc_html(sprintf(__('Authorize %s — connectMWP', 'connectmwp'), $client['client_name'])); ?></title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f0f2f4; color: #1d2327; margin: 0; padding: 2rem 1rem; }
  .cmwp-oauth-card { max-width: 30rem; margin: 0 auto; background: #fff; border: 1px solid #dbe5ed; border-radius: 12px; box-shadow: 0 6px 28px rgba(20,40,60,.08); padding: 28px 30px; }
  .cmwp-oauth-card h1 { font-size: 20px; margin: 0 0 4px; }
  .cmwp-oauth-sub { color: #5a6b78; font-size: 13.5px; margin: 0 0 20px; }
  .cmwp-oauth-app { display: flex; align-items: center; gap: 10px; background: #f7fafc; border: 1px solid #eef2f4; border-radius: 8px; padding: 12px 14px; margin-bottom: 18px; }
  .cmwp-oauth-app strong { font-size: 15px; }
  .cmwp-oauth-rows { margin: 0 0 18px; padding: 0; list-style: none; }
  .cmwp-oauth-rows li { display: flex; justify-content: space-between; gap: 12px; padding: 9px 0; border-bottom: 1px solid #f1f4f6; font-size: 13.5px; }
  .cmwp-oauth-rows li:last-child { border-bottom: 0; }
  .cmwp-oauth-rows .lbl { color: #7f8c8d; }
  .cmwp-oauth-rows .val { font-weight: 600; text-align: right; word-break: break-word; }
  .cmwp-oauth-scope { background: #eef9f4; border: 1px solid #cfeee1; border-radius: 8px; padding: 12px 14px; font-size: 13px; color: #1c5c45; margin-bottom: 18px; line-height: 1.5; }
  .cmwp-oauth-field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 20px; }
  .cmwp-oauth-field span { font-size: 12px; font-weight: 600; color: #7f8c8d; text-transform: uppercase; letter-spacing: .4px; }
  .cmwp-oauth-field select { padding: 9px 11px; border: 1px solid #dbe5ed; border-radius: 7px; font-size: 14px; background: #fff; color: #2c3e50; }
  .cmwp-oauth-actions { display: flex; gap: 10px; }
  .cmwp-oauth-actions button { flex: 1; padding: 11px 14px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; border: 1px solid transparent; }
  .cmwp-btn-approve { background: #16a085; color: #fff; }
  .cmwp-btn-approve:hover { background: #138a72; }
  .cmwp-btn-deny { background: #fff; color: #444; border-color: #d4dee6; }
  .cmwp-btn-deny:hover { background: #f6f8fa; }
  .cmwp-oauth-foot { margin-top: 18px; font-size: 11.5px; color: #93a1ab; line-height: 1.5; text-align: center; }
  .cmwp-oauth-host { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
</head>
<body>
  <div class="cmwp-oauth-card">
    <h1><?php echo esc_html__('Authorize a connection', 'connectmwp'); ?></h1>
    <p class="cmwp-oauth-sub"><?php echo esc_html__('An application is requesting access to publish on this site.', 'connectmwp'); ?></p>

    <div class="cmwp-oauth-app">
      <strong><?php echo esc_html($client['client_name']); ?></strong>
    </div>

    <ul class="cmwp-oauth-rows">
      <li><span class="lbl"><?php echo esc_html__('Site', 'connectmwp'); ?></span><span class="val"><?php echo esc_html($site_name); ?><br><?php echo esc_html($site_url); ?></span></li>
      <li><span class="lbl"><?php echo esc_html__('Will redirect to', 'connectmwp'); ?></span><span class="val cmwp-oauth-host"><?php echo esc_html($redirect_host !== '' ? $redirect_host : $params['redirect_uri']); ?></span></li>
    </ul>

    <div class="cmwp-oauth-scope">
      <strong><?php echo esc_html__('This will grant:', 'connectmwp'); ?></strong><br>
      <?php echo esc_html($scope_desc); ?>
    </div>

    <form method="post" action="<?php echo esc_url($form_action); ?>">
      <label class="cmwp-oauth-field">
        <span><?php echo esc_html__('Connect as', 'connectmwp'); ?></span>
        <select name="connectmwp_oauth_bound_user">
          <?php foreach ($eligible as $u):
              $display = $u->display_name ?: $u->user_login; ?>
            <option value="<?php echo intval($u->ID); ?>" <?php selected($u->ID, $current_id); ?>>
              <?php echo esc_html($display . ' (' . $u->user_login . ')'); ?>
            </option>
          <?php endforeach; ?>
        </select>
      </label>

      <input type="hidden" name="connectmwp_oauth_nonce" value="<?php echo esc_attr($nonce); ?>" />
      <input type="hidden" name="response_type" value="<?php echo esc_attr($params['response_type']); ?>" />
      <input type="hidden" name="client_id" value="<?php echo esc_attr($params['client_id']); ?>" />
      <input type="hidden" name="redirect_uri" value="<?php echo esc_attr($params['redirect_uri']); ?>" />
      <input type="hidden" name="scope" value="<?php echo esc_attr($params['scope']); ?>" />
      <input type="hidden" name="state" value="<?php echo esc_attr($params['state']); ?>" />
      <input type="hidden" name="code_challenge" value="<?php echo esc_attr($params['code_challenge']); ?>" />
      <input type="hidden" name="code_challenge_method" value="<?php echo esc_attr($params['code_challenge_method']); ?>" />
      <input type="hidden" name="resource" value="<?php echo esc_attr($params['resource']); ?>" />

      <div class="cmwp-oauth-actions">
        <button type="submit" class="cmwp-btn-deny" name="connectmwp_oauth_decision" value="deny"><?php echo esc_html__('Deny', 'connectmwp'); ?></button>
        <button type="submit" class="cmwp-btn-approve" name="connectmwp_oauth_decision" value="approve"><?php echo esc_html__('Approve', 'connectmwp'); ?></button>
      </div>
    </form>

    <p class="cmwp-oauth-foot"><?php echo esc_html(sprintf(__('Signed in as %s. Only site administrators can approve connections.', 'connectmwp'), wp_get_current_user()->user_login)); ?></p>
  </div>
</body>
</html>
        <?php
        exit;
    }

    /**
     * [OAuth Phase 1] Plain-English description of the granted scope(s). Single
     * scope today; generic phrasing so it reads correctly for any future scope.
     */
    private function oauth_scope_plain_english(array $scopes) {
        if (in_array('connectmwp', $scopes, true)) {
            return __('Read & write posts, upload media, and manage categories and tags — acting as the user you choose below.', 'connectmwp');
        }
        // Fallback: list the raw scopes (escaped at the call site).
        return sprintf(
            /* translators: %s: space-separated scope list */
            __('The following scopes: %s', 'connectmwp'),
            implode(', ', $scopes)
        );
    }

    /**
     * [OAuth Phase 1] Render a standalone error page (used when we cannot trust a
     * redirect_uri — pre-validation failures). Self-contained HTML, escaped,
     * no admin chrome. exit()s.
     */
    private function oauth_render_error_page($title, $message, $status) {
        if (!headers_sent()) {
            status_header(intval($status));
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('X-Frame-Options: DENY');
            // Self-contained page: no scripts, only inline styles, no forms.
            header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");
            header('X-Content-Type-Options: nosniff');
        }
        ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?php echo esc_html($title); ?> — connectMWP</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f0f2f4; color: #1d2327; margin: 0; padding: 3rem 1rem; }
  .cmwp-oauth-err { max-width: 28rem; margin: 0 auto; background: #fff; border: 1px solid #f3d6d6; border-left: 4px solid #d63638; border-radius: 10px; padding: 24px 28px; }
  .cmwp-oauth-err h1 { font-size: 18px; margin: 0 0 8px; color: #a11; }
  .cmwp-oauth-err p { font-size: 14px; line-height: 1.6; color: #444; margin: 0; }
</style>
</head>
<body>
  <div class="cmwp-oauth-err">
    <h1><?php echo esc_html($title); ?></h1>
    <p><?php echo esc_html($message); ?></p>
  </div>
</body>
</html>
        <?php
        exit;
    }

    /**
     * [OAuth Phase 2] POST /oauth/token — the real token endpoint.
     *
     * Back-channel, form-encoded (application/x-www-form-urlencoded — OAuth token
     * requests are NOT JSON). Two grant types:
     *
     *   authorization_code: redeems a single-use auth code minted by the authorize
     *     endpoint. Verifies client_id, redirect_uri, resource, and the PKCE proof
     *     (S256: base64url(sha256(code_verifier)) === stored code_challenge). On
     *     success issues an access+refresh pair (mint_oauth_tokens).
     *
     *   refresh_token: rotates a presented refresh token (OAuth 2.1 rotation),
     *     issuing a fresh pair bound to the same user/scope/audience. Any attempt
     *     to widen scope or change resource/audience is rejected.
     *
     * Errors are standard OAuth JSON {error, error_description} at HTTP 400, with
     * Cache-Control: no-store. Codes, verifiers, and tokens are NEVER logged.
     *
     * This is a public client (token_endpoint_auth_method=none) — there is no
     * client secret; PKCE (auth_code) / token possession (refresh) is the proof.
     */
    public function oauth_token_handler($request) {
        // HTTPS-first. A token exchange over plaintext would leak the code /
        // verifier / refresh token in transit.
        if (!$this->oauth_request_is_https()) {
            return $this->oauth_token_error('invalid_request', __('HTTPS is required for the token endpoint.', 'connectmwp'));
        }

        // M-rate: per-IP failure limiter, mirroring the /mcp cgpt verifier limiter.
        // Only FAILED grants are counted (a successful exchange never increments),
        // so a legitimate client refreshing on schedule is never throttled. The IP
        // is hashed into the key so no raw PII lands in an option name. This is
        // defense-in-depth/DoS — token entropy already defeats brute force.
        $ip = $this->get_client_ip();
        $limit_key = 'cmwp_oauth_token_limit_' . md5($ip);
        $failures  = intval(get_transient($limit_key));
        if ($failures >= self::OAUTH_TOKEN_MAX_FAILURES) {
            $response = new WP_REST_Response([
                'error'             => 'temporarily_unavailable',
                'error_description' => __('Too many failed token requests from this IP. Please try again later.', 'connectmwp'),
            ], 429);
            $response->header('Cache-Control', 'no-store');
            $response->header('Pragma', 'no-cache');
            return $response;
        }

        // OAuth token requests are application/x-www-form-urlencoded. WP_REST_Request
        // parses that into body params. We deliberately read body params (NOT JSON)
        // so a JSON-bodied request simply yields no grant_type → invalid_request.
        $param = function ($name) use ($request) {
            if ($request instanceof WP_REST_Request) {
                $v = $request->get_body_params();
                if (is_array($v) && isset($v[$name])) {
                    return is_string($v[$name]) ? trim($v[$name]) : '';
                }
            }
            return '';
        };

        $grant_type = $param('grant_type');
        if ($grant_type === '') {
            return $this->oauth_token_count_failure($limit_key, $failures,
                $this->oauth_token_error('invalid_request', __('Missing grant_type.', 'connectmwp')));
        }

        if ($grant_type === 'authorization_code') {
            return $this->oauth_token_count_failure($limit_key, $failures,
                $this->oauth_token_grant_authorization_code($param));
        }
        if ($grant_type === 'refresh_token') {
            return $this->oauth_token_count_failure($limit_key, $failures,
                $this->oauth_token_grant_refresh($param));
        }

        return $this->oauth_token_count_failure($limit_key, $failures,
            $this->oauth_token_error('unsupported_grant_type', __('Unsupported grant_type.', 'connectmwp')));
    }

    /**
     * [OAuth Phase 2] M-rate helper: increment the per-IP /oauth/token failure
     * counter when a grant produced an error response (HTTP >= 400), and leave a
     * successful exchange untouched. Returns $response unchanged so callers can
     * `return $this->oauth_token_count_failure(...)` inline. Best-effort transient
     * (not strictly atomic) — acceptable for a volume throttle on a 256-bit secret.
     */
    private function oauth_token_count_failure($limit_key, $failures, $response) {
        $status = ($response instanceof WP_REST_Response) ? intval($response->get_status()) : 400;
        if ($status >= 400) {
            set_transient($limit_key, $failures + 1, self::OAUTH_TOKEN_LOCKOUT_SECONDS);
        }
        return $response;
    }

    /**
     * [OAuth Phase 2] authorization_code grant. Single-use code redemption + PKCE
     * verification, then issue an access+refresh pair.
     *
     * @param callable $param fn(string $name): string — trimmed body param reader.
     */
    private function oauth_token_grant_authorization_code(callable $param) {
        $code          = $param('code');
        $code_verifier = $param('code_verifier');
        $redirect_uri  = $param('redirect_uri');
        $client_id     = $param('client_id');
        $resource      = $param('resource');

        if ($code === '' || $code_verifier === '' || $redirect_uri === '' || $client_id === '') {
            return $this->oauth_token_error('invalid_request', __('Missing one or more required parameters (code, code_verifier, redirect_uri, client_id).', 'connectmwp'));
        }

        // RFC 7636: code_verifier is 43..128 chars from the unreserved set
        // [A-Za-z0-9-._~]. Reject anything outside that before hashing.
        if (!preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $code_verifier)) {
            return $this->oauth_token_error('invalid_grant', __('Malformed PKCE code_verifier.', 'connectmwp'));
        }

        // Redeem the code ONCE. consume_oauth_code atomically deletes the row and
        // enforces the TTL, returning the bound grant or false.
        $grant = $this->consume_oauth_code($code);
        if ($grant === false) {
            return $this->oauth_token_error('invalid_grant', __('Authorization code is invalid, expired, or already used.', 'connectmwp'));
        }

        // Bind checks. client_id and redirect_uri must match the grant the code was
        // issued against (constant-time compare — these gate credential issuance).
        if (!hash_equals((string) $grant['client_id'], $client_id)) {
            return $this->oauth_token_error('invalid_grant', __('client_id does not match the authorization code.', 'connectmwp'));
        }
        if (!hash_equals((string) $grant['redirect_uri'], $redirect_uri)) {
            return $this->oauth_token_error('invalid_grant', __('redirect_uri does not match the authorization code.', 'connectmwp'));
        }

        // If the client sends `resource`, it must match the grant's bound resource.
        // Absent `resource` is tolerated — the grant already pins the audience. A
        // PRESENT but mismatching resource is rejected. TWO independent checks
        // (RFC 8707):
        //   (a) the presented resource must equal this site's canonical /mcp URI;
        //   (b) the presented resource must equal the resource BOUND TO THE GRANT
        //       (the resource the authorization code was issued against).
        // Today (a) and (b) are equal, but binding the token request's resource to
        // the grant's stored resource is the architecturally-required check — it
        // stays correct across a site migration or a `rest_url` filter change that
        // would shift the live canonical URI away from a still-valid grant.
        if ($resource !== '') {
            if (!$this->oauth_resource_matches($resource)) {
                return $this->oauth_token_error('invalid_target', __('resource does not match the authorized audience.', 'connectmwp'));
            }
            $grant_resource = isset($grant['resource']) ? (string) $grant['resource'] : '';
            $presented_norm = $this->oauth_normalize_resource_for_compare($resource);
            $grant_norm     = $this->oauth_normalize_resource_for_compare($grant_resource);
            if ($presented_norm === null || $grant_norm === null || !hash_equals($grant_norm, $presented_norm)) {
                return $this->oauth_token_error('invalid_target', __('resource does not match the resource bound to the authorization code.', 'connectmwp'));
            }
        }

        // PKCE proof (S256 only — the authorize endpoint requires S256 and stores
        // it that way). base64url(sha256(code_verifier)) must equal the stored
        // code_challenge. Constant-time compare of the derived challenge.
        $method = isset($grant['code_challenge_method']) ? (string) $grant['code_challenge_method'] : '';
        if ($method !== 'S256') {
            // Defensive: the authorize side only ever mints S256. Anything else is
            // a corrupt/forged grant.
            return $this->oauth_token_error('invalid_grant', __('Unsupported PKCE method on the authorization code.', 'connectmwp'));
        }
        $derived_challenge = $this->oauth_base64url_encode(hash('sha256', $code_verifier, true));
        if (!hash_equals((string) $grant['code_challenge'], $derived_challenge)) {
            return $this->oauth_token_error('invalid_grant', __('PKCE verification failed.', 'connectmwp'));
        }

        // All checks passed — issue the token pair.
        $tokens = $this->mint_oauth_tokens($grant);
        if ($tokens === false) {
            return $this->oauth_token_error('temporarily_unavailable', __('Could not issue tokens; please try again shortly.', 'connectmwp'));
        }

        return $this->oauth_token_success($tokens);
    }

    /**
     * [OAuth Phase 2] refresh_token grant. Validate + rotate the refresh token,
     * refusing any attempt to widen scope or change the audience/resource.
     *
     * @param callable $param fn(string $name): string — trimmed body param reader.
     */
    private function oauth_token_grant_refresh(callable $param) {
        $refresh_token = $param('refresh_token');
        $req_scope     = $param('scope');
        $req_resource  = $param('resource');

        if ($refresh_token === '') {
            return $this->oauth_token_error('invalid_request', __('Missing refresh_token.', 'connectmwp'));
        }

        // I-2: PEEK before ROTATE. The no-widen scope/audience checks must run
        // against the stored record BEFORE we consume (rotate) the refresh token —
        // otherwise an innocent/mistaken widen request would permanently destroy a
        // client's working refresh token (rotate atomically deletes it). The peek
        // is read-only: single-use is still guaranteed solely by rotate's atomic
        // delete (a concurrent double-rotate: only one delete wins, the other
        // fails closed). Scope/audience on the new pair still come verbatim from
        // the stored record and are never widened.
        $peek = $this->peek_oauth_refresh_token($refresh_token);
        if ($peek === false) {
            return $this->oauth_token_error('invalid_grant', __('Refresh token is invalid, expired, or already used.', 'connectmwp'));
        }
        $stored = $peek['record'];

        // No-widen guard for `resource` (audience). If the client supplies one it
        // must (a) match THIS site's canonical /mcp URI and (b) equal the audience
        // the refresh token is bound to. Rejected WITHOUT consuming the token.
        if ($req_resource !== '') {
            if (!$this->oauth_resource_matches($req_resource)) {
                return $this->oauth_token_error('invalid_target', __('resource does not match the token audience.', 'connectmwp'));
            }
            $req_norm    = $this->oauth_normalize_resource_for_compare($req_resource);
            $stored_aud  = isset($stored['audience']) ? (string) $stored['audience'] : '';
            $stored_norm = $this->oauth_normalize_resource_for_compare($stored_aud);
            if ($req_norm === null || $stored_norm === null || !hash_equals($stored_norm, $req_norm)) {
                return $this->oauth_token_error('invalid_target', __('resource does not match the token audience.', 'connectmwp'));
            }
        }

        // No-widen scope guard: if the client asked for a scope, it may only be a
        // SUBSET of the granted scope. (Single-scope today, but enforce generally
        // so a future multi-scope world can't widen.) Rejected WITHOUT consuming
        // the token — checked against the PEEKED stored record, not the rotated
        // output.
        if ($req_scope !== '') {
            $granted = $this->oauth_parse_scope(isset($stored['scope']) ? (string) $stored['scope'] : '');
            $asked   = $this->oauth_parse_scope($req_scope);
            $extra   = array_diff($asked, $granted);
            if (!empty($extra)) {
                return $this->oauth_token_error('invalid_scope', __('Requested scope exceeds the originally granted scope.', 'connectmwp'));
            }
        }

        // All no-widen checks passed — NOW consume + reissue atomically. The race
        // between peek and rotate is benign: rotate's atomic delete still wins-once
        // (a concurrent rotate of the same token gets one success, the other false
        // -> invalid_grant). Scope/audience on the new pair come verbatim from the
        // stored record (never widened).
        $tokens = $this->rotate_oauth_refresh_token($refresh_token);
        if ($tokens === false) {
            return $this->oauth_token_error('invalid_grant', __('Refresh token is invalid, expired, or already used.', 'connectmwp'));
        }

        return $this->oauth_token_success($tokens);
    }

    /**
     * [OAuth Phase 2] Build the success token response. Always no-store / no-cache
     * (the body carries secrets that must never be cached).
     *
     * @param array $tokens From mint_oauth_tokens / rotate_oauth_refresh_token.
     */
    private function oauth_token_success(array $tokens) {
        $response = new WP_REST_Response([
            'access_token'  => $tokens['access_token'],
            'token_type'    => 'Bearer',
            'expires_in'    => intval($tokens['expires_in']),
            'refresh_token' => $tokens['refresh_token'],
            'scope'         => isset($tokens['scope']) && $tokens['scope'] !== '' ? $tokens['scope'] : implode(' ', self::OAUTH_SUPPORTED_SCOPES),
        ], 200);
        $response->header('Cache-Control', 'no-store');
        $response->header('Pragma', 'no-cache');
        return $response;
    }

    /**
     * [OAuth Phase 2] Standard OAuth error response: JSON {error, error_description}
     * at HTTP 400, Cache-Control: no-store. error_description is a fixed,
     * non-sensitive string (never echoes a presented secret).
     */
    private function oauth_token_error($error, $description) {
        $response = new WP_REST_Response([
            'error'             => (string) $error,
            'error_description' => (string) $description,
        ], 400);
        $response->header('Cache-Control', 'no-store');
        $response->header('Pragma', 'no-cache');
        return $response;
    }

    /**
     * [OAuth Phase 2] URL-safe base64 (RFC 4648 §5) WITHOUT padding — the encoding
     * PKCE S256 uses for code_challenge. Mirrors the client-side
     * base64url(sha256(verifier)). Keep byte-identical to whatever the authorize
     * side stored (it stores the client-supplied code_challenge verbatim, which is
     * itself unpadded base64url per RFC 7636).
     */
    private function oauth_base64url_encode($raw) {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Register Custom WordPress REST API Routes
     */
    public function register_rest_routes() {
        // Enrollment route (public, validated by code)
        register_rest_route(self::API_NAMESPACE, '/enroll', [
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'enroll_client_handler'],
                'permission_callback' => '__return_true',
            ]
        ]);

        // Identity / connection-verification route — signature-authenticated, no capability
        // required. Lets a freshly-paired client confirm end-to-end signing works and
        // discover what user it acts as + what capabilities it has on this site.
        register_rest_route(self::API_NAMESPACE, '/whoami', [
            [
                'methods'             => 'GET',
                'callback'            => [$this, 'whoami_handler'],
                'permission_callback' => [$this, 'check_signature_only'],
            ]
        ]);

        register_rest_route(self::API_NAMESPACE, '/posts', [
            [
                'methods'             => 'GET',
                'callback'            => [$this, 'get_posts_handler'],
                'permission_callback' => [$this, 'check_read_permission'],
            ],
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'create_post_handler'],
                'permission_callback' => [$this, 'check_edit_permission'],
            ]
        ]);

        register_rest_route(self::API_NAMESPACE, '/posts/(?P<id>\d+)', [
            [
                'methods'             => 'GET',
                'callback'            => [$this, 'get_post_handler'],
                'permission_callback' => [$this, 'check_read_permission'],
            ],
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'update_post_handler'],
                'permission_callback' => [$this, 'check_edit_post_permission'],
            ],
            [
                'methods'             => 'DELETE',
                'callback'            => [$this, 'delete_post_handler'],
                'permission_callback' => [$this, 'check_delete_post_permission'],
            ]
        ]);

        register_rest_route(self::API_NAMESPACE, '/media', [
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'upload_media_handler'],
                'permission_callback' => [$this, 'check_upload_permission'],
            ]
        ]);

        register_rest_route(self::API_NAMESPACE, '/tags', [
            [
                'methods'             => 'GET',
                'callback'            => [$this, 'get_tags_handler'],
                'permission_callback' => [$this, 'check_read_permission'],
            ],
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'create_tag_handler'],
                'permission_callback' => [$this, 'check_taxonomy_permission'],
            ]
        ]);

        register_rest_route(self::API_NAMESPACE, '/categories', [
            [
                'methods'             => 'GET',
                'callback'            => [$this, 'get_categories_handler'],
                'permission_callback' => [$this, 'check_read_permission'],
            ],
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'create_category_handler'],
                'permission_callback' => [$this, 'check_taxonomy_permission'],
            ]
        ]);

        // Remote MCP (JSON-RPC 2.0) endpoint for ChatGPT and other HTTP MCP
        // clients. Authenticated by a bearer TOKEN via verify_token_request (NOT
        // the Ed25519 signature path — see the C-1 bypass in central_rest_auth).
        // The permission_callback is the auth boundary; it MUST NOT be
        // '__return_true'. Tool execution flows through dispatch_action so the
        // per-action capability checks and handlers are shared with the
        // signature/AJAX transports (SSOT — no duplicated publish/capability logic).
        register_rest_route(self::API_NAMESPACE, '/mcp', [
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'mcp_handler'],
                'permission_callback' => [$this, 'verify_token_request'],
            ]
        ]);

        // Path-token variant: managed hosts (SiteGround, Kinsta, WP Engine) strip
        // the standard Authorization header at the edge proxy. Carrying the token
        // as a URL path segment survives that. verify_token_request reads the
        // `token` route param as its 3rd-precedence source. Regex is constrained to
        // the token alphabet ([A-Za-z0-9_-]) — no slashes or encoded chars — so the
        // segment can never smuggle additional path structure.
        register_rest_route(self::API_NAMESPACE, '/mcp/(?P<token>[A-Za-z0-9_-]+)', [
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'mcp_handler'],
                'permission_callback' => [$this, 'verify_token_request'],
            ]
        ]);

        // [OAuth Phase 1] The authorization endpoint is intentionally NOT a REST
        // route. It is served as a normal cookie-native FRONT-END page at
        // OAUTH_AUTHORIZE_PATH via oauth_authorize_router() (REQUEST_URI
        // interception on parse_request). A REST route would require a valid REST
        // nonce (X-WP-Nonce/_wpnonce) before WP establishes the logged-in user
        // from the auth cookie — and a third-party OAuth redirect (browser hitting
        // the authorize URL) cannot supply that nonce, which caused an infinite
        // wp-login loop. See oauth_authorize_router / oauth_authorize_handler.

        // [OAuth Phase 2] The token endpoint is now REAL. It is a back-channel
        // POST from the client's own server (no browser cookie), so it is NOT
        // signature-gated and NOT capability-gated: it authenticates the request
        // by the single-use authorization code + PKCE code_verifier (auth_code
        // grant) or by a valid refresh token (refresh grant). It stays exempted
        // from the Ed25519 signature gate in central_rest_auth (the auth model is
        // PKCE/refresh, not a signature), and emits its own no-store headers. The
        // permission_callback is __return_true ONLY because the grant material IS
        // the credential, validated inside the handler. Do NOT add a signature
        // requirement here — public OAuth clients have no signing key.
        register_rest_route(self::API_NAMESPACE, '/oauth/token', [
            [
                'methods'             => 'POST',
                'callback'            => [$this, 'oauth_token_handler'],
                'permission_callback' => '__return_true',
            ]
        ]);
    }

    public function central_rest_auth($result, $server, $request) {
        $route = $request->get_route();

        if (strpos($route, '/' . self::API_NAMESPACE . '/') === 0) {
            // Prevent edge/page caches (e.g. LiteSpeed, common on managed hosts)
            // from storing signed REST responses. Because auth is session-less,
            // WordPress does not auto-send no-cache for these requests, so a cached
            // GET would otherwise be served to UNAUTHENTICATED callers — bypassing
            // signature verification and leaking draft/private content.
            $this->send_rest_nocache_headers();

            if ($route === '/' . self::API_NAMESPACE . '/enroll') {
                return $result;
            }

            // C-1 bypass (the ONLY signature-gate exception besides /enroll):
            // the MCP/JSON-RPC endpoint is authenticated by a bearer TOKEN, not an
            // Ed25519 signature, so the signature gate would always reject it. Auth
            // is NOT bypassed here — it is enforced one layer down by the route's
            // permission_callback (verify_token_request), which sets the bound user
            // exactly as the signature path does. The no-cache headers above ALREADY
            // fired for /mcp, so cache-poisoning protection is preserved. This block
            // must run AFTER send_rest_nocache_headers() and BEFORE
            // verify_request_signature(). Do NOT remove.
            if ($route === '/' . self::API_NAMESPACE . '/mcp'
                || strpos($route, '/' . self::API_NAMESPACE . '/mcp/') === 0) {
                return $result; // token-authenticated path; permission_callback (verify_token_request) handles auth.
            }

            // Exempt the back-channel /oauth/token REST endpoint from the Ed25519
            // signature gate. The signature gate is the wrong auth model for it:
            // /oauth/token authenticates via the PKCE code-verifier + single-use
            // auth code (auth_code grant) or a valid refresh token (refresh
            // grant), NOT a signature. NOTE: /oauth/authorize is NOT a REST route
            // — it is served as a cookie-native FRONT-END page at
            // OAUTH_AUTHORIZE_PATH (see oauth_authorize_router), so it never
            // reaches this filter and is not listed here. The match is a TIGHT,
            // exact list; it does NOT loosen the /mcp match above.
            if ($route === '/' . self::API_NAMESPACE . '/oauth/token') {
                return $result;
            }

            if (!$this->verify_request_signature($request)) {
                $code = $this->verification_error_code ?: 'connectmwp_unauthorized';
                return new WP_Error(
                    $code,
                    $this->describe_verification_error($code),
                    ['status' => 401]
                );
            }
        }

        return $result;
    }

    /**
     * Map a verification_error_code to a human-readable message that's safe
     * to expose to the MCP client (no internal state — caller can already see
     * the URL, the headers they sent, and the timestamp; codes are not secret).
     */
    private function describe_verification_error($code) {
        switch ($code) {
            case 'connectmwp_missing_nonce':
                return 'Request missing X-ConnectMWP-Nonce header. Client is older than v2.0.19 — upgrade by re-pairing: npx -y connectmwp-mcp add-site --enroll "<site_url>,<pairing_code>".';
            case 'connectmwp_invalid_nonce_format':
                return 'X-ConnectMWP-Nonce header is not a valid UUID.';
            case 'connectmwp_missing_credentials':
                return 'Request missing one or more required ConnectMWP auth headers.';
            case 'connectmwp_timestamp_skew':
                return 'Request timestamp is outside the ±300s clock-skew window.';
            case 'connectmwp_unknown_key':
                return 'X-ConnectMWP-Key does not match any paired client on this site.';
            case 'connectmwp_malformed_credentials':
                return 'Public key or signature is the wrong length for Ed25519.';
            case 'connectmwp_sodium_missing':
                return 'PHP libsodium extension is not available on this host.';
            case 'connectmwp_signature_invalid':
                return 'Signature verification failed.';
            case 'connectmwp_replay_detected':
                return 'Signature was already used within the replay window (this request is a replay).';
            case 'connectmwp_cgpt_insecure_transport':
                return 'HTTPS is required for token-authenticated requests.';
            case 'connectmwp_cgpt_missing_token':
                return 'Request missing a ChatGPT API token (Authorization: Bearer, X-ConnectMWP-Token header, or token route param).';
            case 'connectmwp_cgpt_invalid_token':
                return 'ChatGPT API token does not match any active token on this site.';
            case 'connectmwp_cgpt_rate_limited':
                return 'Too many failed token attempts from this IP. Please try again later.';
            case 'connectmwp_cgpt_unbound_token':
                return 'ChatGPT API token is not bound to a valid user; regenerate it from the connectMWP settings page.';
            case 'connectmwp_oauth_invalid_token':
                return 'OAuth access token is invalid, expired, or not valid for this resource.';
            case 'connectmwp_oauth_unbound_token':
                return 'OAuth access token is not bound to a valid user; re-authorize from your AI client.';
            default:
                return 'Unauthorized request signature verification failed.';
        }
    }

    /**
     * Force caches not to store connectMWP REST responses (defense against the
     * cache-based auth bypass described in central_rest_auth).
     */
    private function send_rest_nocache_headers() {
        if (!defined('DONOTCACHEPAGE')) {
            define('DONOTCACHEPAGE', true);
        }
        if (function_exists('nocache_headers')) {
            nocache_headers();
        }
        if (!headers_sent()) {
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0', true);
            header('X-LiteSpeed-Cache-Control: no-cache', true);
        }
        // Authoritative LiteSpeed control hook.
        do_action('litespeed_control_set_nocache', 'connectmwp signed api response');
    }

    private $signature_verified = null;
    private $bound_user_id = 0;
    private $matched_key_id = '';

    // Per-request verdict cache for the ChatGPT bearer-token path (T3),
    // analogous to $signature_verified. Null = not yet evaluated this request;
    // true/false = the cached outcome. WP can invoke a permission_callback
    // multiple times per request, so caching here both avoids re-scanning the
    // token index AND prevents a stale "miss" from re-incrementing the IP
    // failure counter on the second invocation. A cached PASS re-establishes
    // $this->bound_user_id so the existing check_* callbacks authorize via the
    // bound user exactly as they do on the signature path.
    private $cgpt_token_verified = null;

    // The bound user id resolved by the most recent SUCCESSFUL token
    // verification. Stored separately from $this->bound_user_id because the
    // latter is reset to 0 at the top of every verify_token_request() call
    // (I-1 defensive reset); on a cached PASS we restore it from here so a
    // second permission_callback invocation never returns true with
    // bound_user_id == 0.
    private $cgpt_bound_user_id = 0;

    // True only when the most recent dispatch_action() call short-circuited at a
    // dispatch GATE (capability-check failure or unknown-action default) before
    // invoking any handler. Transport-neutral metadata about WHERE the response
    // originated -- consumed by handle_ajax_request() to reproduce the legacy
    // wrapped {success:false,data:{error}} envelope for gate errors only, while
    // emitting every handler response (success AND error alike) flat. Reset at
    // the top of each dispatch_action() call so a stale value can never leak.
    private $last_dispatch_gated = false;

    // Specific reason the most recent verification failed. Surfaced through
    // central_rest_auth + handle_ajax_request as the WP_Error code so the MCP
    // client (and support) can recognize "pinned-old-client" (missing nonce),
    // "replay detected", or "signature mismatch" at a glance. Empty string
    // when verification succeeded or has not yet run.
    private $verification_error_code = '';

    /**
     * Verify the detached Ed25519 request signature
     */
    private function verify_request_signature($request = null) {
        if ($this->signature_verified !== null) {
            return $this->signature_verified;
        }

        // 1. Enforce HTTPS (shared SSOT gate; on a non-proxy site this is
        // byte-identical to is_ssl() — the forwarded-proto branch is unreachable
        // unless the admin opted into proxy trust).
        if (!$this->is_https_request()) {
            $this->signature_verified = false;
            return false;
        }

        // 2. Extract headers
        $key_id = '';
        $timestamp = '';
        $signature_b64 = '';
        $nonce = '';

        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'X-ConnectMWP-Key') === 0) {
                    $key_id = $value;
                } elseif (strcasecmp($name, 'X-ConnectMWP-Timestamp') === 0) {
                    $timestamp = $value;
                } elseif (strcasecmp($name, 'X-ConnectMWP-Signature') === 0) {
                    $signature_b64 = $value;
                } elseif (strcasecmp($name, 'X-ConnectMWP-Nonce') === 0) {
                    $nonce = $value;
                }
            }
        }

        if (empty($key_id) && isset($_SERVER['HTTP_X_CONNECTMWP_KEY'])) {
            $key_id = $_SERVER['HTTP_X_CONNECTMWP_KEY'];
        }
        if (empty($timestamp) && isset($_SERVER['HTTP_X_CONNECTMWP_TIMESTAMP'])) {
            $timestamp = $_SERVER['HTTP_X_CONNECTMWP_TIMESTAMP'];
        }
        if (empty($signature_b64) && isset($_SERVER['HTTP_X_CONNECTMWP_SIGNATURE'])) {
            $signature_b64 = $_SERVER['HTTP_X_CONNECTMWP_SIGNATURE'];
        }
        if (empty($nonce) && isset($_SERVER['HTTP_X_CONNECTMWP_NONCE'])) {
            $nonce = $_SERVER['HTTP_X_CONNECTMWP_NONCE'];
        }

        if (empty($key_id) || empty($timestamp) || empty($signature_b64)) {
            $this->verification_error_code = 'connectmwp_missing_credentials';
            $this->signature_verified = false;
            return false;
        }

        // Hard cut on missing nonce: any client below v2.0.19 fails here with
        // a distinct code so support can recognize "pinned-old-client" at a
        // glance (vs a generic signature failure). Re-pairing via
        // `npx -y connectmwp-mcp add-site --enroll ...` fetches the current
        // client which sends the nonce.
        if (empty($nonce)) {
            $this->verification_error_code = 'connectmwp_missing_nonce';
            $this->signature_verified = false;
            return false;
        }

        // RFC 4122 UUID shape (any version). Rejects junk values before they
        // reach the canonical rebuild.
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $nonce)) {
            $this->verification_error_code = 'connectmwp_invalid_nonce_format';
            $this->signature_verified = false;
            return false;
        }

        // 3. Verify timestamp skew (within ±300s)
        if (abs(time() - intval($timestamp)) > self::TIMESTAMP_SKEW_SECONDS) {
            $this->verification_error_code = 'connectmwp_timestamp_skew';
            $this->signature_verified = false;
            return false;
        }

        // 4. Look up client key
        $key_config = $this->find_key_by_id($key_id);
        if (!$key_config) {
            $this->verification_error_code = 'connectmwp_unknown_key';
            $this->signature_verified = false;
            return false;
        }

        $pub_key_b64 = $key_config['public_key'];
        $bound_user_id = intval($key_config['bound_user_id']);

        // 5. Rebuild canonical string
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        
        // Path logic (survive subdirectories and REST routing parameters)
        $request_path = '';
        if (isset($_REQUEST['action']) && $_REQUEST['action'] === 'connectmwp_api' && isset($_REQUEST['connectmwp_action'])) {
            $action = sanitize_key($_REQUEST['connectmwp_action']);
            $request_path = '/connectmwp/v1/' . $action;
        } elseif ($request instanceof WP_REST_Request) {
            $request_path = $request->get_route();
        } else {
            $request_uri = $_SERVER['REQUEST_URI'] ?? '';
            $request_path = explode('?', $request_uri)[0];
            if (isset($_GET['rest_route'])) {
                $request_path = explode('?', $_GET['rest_route'])[0];
            }
        }

        // Sort query parameters alphabetically and hash
        $query_params = [];
        if ($method === 'GET') {
            if ($request instanceof WP_REST_Request) {
                $query_params = $request->get_query_params();
            } else {
                $query_params = $_GET;
            }
        }
        unset($query_params['rest_route']);
        ksort($query_params);
        $sorted_query = http_build_query($query_params, '', '&', PHP_QUERY_RFC3986);
        $query_hash = hash('sha256', $sorted_query);

        // Body hash (skip hashing multipart/form-data body to avoid boundary mismatches, read from header instead)
        $body_hash = '';
        $content_type = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
        if (stripos($content_type, 'multipart/form-data') !== false) {
            $body_hash = $_SERVER['HTTP_X_CONNECTMWP_BODY_HASH'] ?? $_SERVER['X_CONNECTMWP_BODY_HASH'] ?? '';
        } else {
            $raw_body = file_get_contents('php://input');
            $body_hash = hash('sha256', $raw_body ?? '');
        }

        // Canonical field order MUST match the MCP client's reconstruction in
        // callWordPress / callWordPressAjax (connectmwp-mcp/index.js). The
        // nonce field sits between timestamp and method as of v2.0.19.
        $canonical = implode("\n", [
            $timestamp,
            $nonce,
            strtoupper($method),
            $request_path,
            $query_hash,
            $body_hash
        ]);

        // 6. Verify signature using libsodium
        $pub_key_raw = base64_decode($pub_key_b64);
        $sig_raw = base64_decode($signature_b64);

        if (strlen($pub_key_raw) !== 32 || strlen($sig_raw) !== 64) {
            $this->verification_error_code = 'connectmwp_malformed_credentials';
            $this->signature_verified = false;
            return false;
        }

        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            $this->verification_error_code = 'connectmwp_sodium_missing';
            $this->signature_verified = false;
            return false;
        }

        $verified = sodium_crypto_sign_verify_detached($sig_raw, $canonical, $pub_key_raw);
        if (!$verified) {
            $this->verification_error_code = 'connectmwp_signature_invalid';
            $this->signature_verified = false;
            return false;
        }

        // 7. Replay attack check. The existing sig-hash cache stays as the
        // structural replay defense; the new nonce field in the canonical
        // makes every signature unique by construction so the cache continues
        // to catch any literal replay attempt naturally.
        $sig_hash = hash('sha256', $signature_b64);
        if ($this->is_replay_signature($sig_hash)) {
            $this->verification_error_code = 'connectmwp_replay_detected';
            $this->signature_verified = false;
            return false;
        }

        // Success - Cache verification state
        $this->bound_user_id = $bound_user_id;
        $this->matched_key_id = $key_id;
        $this->signature_verified = true;
        
        $this->update_key_last_used($bound_user_id, $key_id);

        return true;
    }

    /**
     * Verify a ChatGPT-style bearer API token (T3). Callable as a REST
     * permission_callback. On success, sets $this->bound_user_id so the
     * existing per-route check_* callbacks (check_read_permission, etc.)
     * authorize via user_can($this->bound_user_id, ...) with NO change — the
     * token path and the signature path converge on the same bound-user state.
     *
     * Like the signature path, this NEVER establishes a login session: no
     * wp_set_current_user, no determine_current_user, no get_current_user_id().
     *
     * Verification order (mirrors verify_request_signature):
     *   VR-5 HTTPS gate → VR-1 per-request verdict cache → token extraction
     *   → VR-1 IP rate-limit (failed resolves only) → resolve → VR-6 bind user
     *   + VR-4 touch-on-success.
     *
     * Returns true on success; on every failure path returns a WP_Error whose
     * 'status' data drives the HTTP response code (WP honors a WP_Error
     * returned from a permission_callback) and whose code carries the
     * connectmwp_cgpt_* diagnostic that a plain `return false` would otherwise
     * collapse into a generic 403.
     *
     * @param WP_REST_Request|null $request
     * @return bool|WP_Error true on success, WP_Error on failure.
     */
    public function verify_token_request($request = null) {
        // I-1: Defensive state reset. bound_user_id is shared with the signature
        // path; clear it at entry (BEFORE the cache check) so no stale bound user
        // from any prior code path can bleed into a token request. The
        // cached-PASS branch below re-establishes it from $this->cgpt_bound_user_id
        // so a cache hit never returns true with bound_user_id == 0.
        $this->bound_user_id = 0;

        // VR-5: Enforce HTTPS first (shared SSOT gate so the bearer-token verifier
        // agrees with the OAuth authorize/token handlers — otherwise a reverse-proxy
        // site can mint a token via OAuth and then have it rejected here).
        if (!$this->is_https_request()) {
            $this->verification_error_code = 'connectmwp_cgpt_insecure_transport';
            $this->cgpt_token_verified = false;
            return new WP_Error(
                'connectmwp_cgpt_insecure_transport',
                $this->describe_verification_error('connectmwp_cgpt_insecure_transport'),
                array('status' => 403)
            );
        }

        // VR-1: Per-request verdict cache. WP may invoke a permission_callback
        // multiple times; on the second invocation return the cached verdict
        // without re-scanning the token index or re-touching the failure
        // counter. On a cached PASS, restore the resolved bound user (the entry
        // reset above zeroed it) so the check_* callbacks read the right id —
        // a cached pass NEVER returns true with bound_user_id == 0.
        if ($this->cgpt_token_verified !== null) {
            if ($this->cgpt_token_verified === true) {
                $this->bound_user_id = $this->cgpt_bound_user_id;
                return true;
            }
            // Cached failure: re-emit the original diagnostic + status.
            $code = $this->verification_error_code ?: 'connectmwp_cgpt_invalid_token';
            $cached_status = $this->cgpt_status_for_code($code);
            // Re-emit the discovery challenge on a cached
            // 401 too (WP may invoke this permission_callback twice per request).
            if ($cached_status === 401) {
                $this->oauth_emit_www_authenticate();
            }
            return new WP_Error(
                $code,
                $this->describe_verification_error($code),
                array('status' => $cached_status)
            );
        }

        // Extract the presented token in precedence order:
        //   (a) Authorization: Bearer <token>
        //   (b) X-ConnectMWP-Token: <token>
        //   (c) route param `token` (T4's /mcp/(?P<token>...) variant)
        $authorization = '';
        $custom_token  = '';

        if ($request instanceof WP_REST_Request) {
            $authorization = (string) $request->get_header('Authorization');
            $custom_token  = (string) $request->get_header('X-ConnectMWP-Token');
        } elseif (function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'Authorization') === 0) {
                    $authorization = $value;
                } elseif (strcasecmp($name, 'X-ConnectMWP-Token') === 0) {
                    $custom_token = $value;
                }
            }
        }

        // Non-REST fallback for either header (mirrors verify_request_signature).
        if ($authorization === '' && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorization = $_SERVER['HTTP_AUTHORIZATION'];
        }
        if ($custom_token === '' && isset($_SERVER['HTTP_X_CONNECTMWP_TOKEN'])) {
            $custom_token = $_SERVER['HTTP_X_CONNECTMWP_TOKEN'];
        }

        $token = '';
        if ($authorization !== '') {
            // Strip a leading "Bearer " (case-insensitive) if present.
            // M-2: an Authorization value WITHOUT a recognized "Bearer " prefix
            // is intentionally accepted verbatim as the token. resolve_cgpt_token's
            // prefix/length prefilter rejects anything malformed, so accepting the
            // raw value here means non-standard or absent schemes don't silently
            // break paste-the-token setups.
            if (stripos($authorization, 'Bearer ') === 0) {
                $token = trim(substr($authorization, 7));
            } else {
                $token = trim($authorization);
            }
        }
        if ($token === '' && $custom_token !== '') {
            $token = trim($custom_token);
        }
        // Source (c): the `token` route param of the /mcp/<token> path-token
        // route is ONLY honored when the admin has explicitly opted in to the
        // URL-embedded fallback (OFF by default — sec review MEDIUM: a path token
        // lands in server/CDN access logs). When disabled, a request that carries
        // only a path token (no header token) falls through to the
        // connectmwp_cgpt_missing_token 401 below. The HEADER sources above are
        // never gated. The route stays registered; it is simply inert here.
        if ($token === '' && $this->cgpt_path_token_enabled() && $request instanceof WP_REST_Request) {
            $route_token = $request->get_param('token');
            if (is_string($route_token)) {
                $token = trim($route_token);
            }
        }

        if ($token === '') {
            $this->verification_error_code = 'connectmwp_cgpt_missing_token';
            $this->cgpt_token_verified = false;
            // Emit the RFC 9728 discovery challenge on the
            // unauthenticated /mcp 401. This is what tells an OAuth-capable client
            // (ChatGPT) to begin discovery against our .well-known docs. Only on
            // this no-credentials 401 — a valid token request never reaches here.
            $this->oauth_emit_www_authenticate();
            return new WP_Error(
                'connectmwp_cgpt_missing_token',
                $this->describe_verification_error('connectmwp_cgpt_missing_token'),
                array('status' => 401)
            );
        }

        // VR-1: IP rate-limit BEFORE the (relatively expensive) index-scanning
        // resolve. Only FAILED resolves count toward the limit (see below), so
        // a legitimate client making many authenticated calls is never locked.
        //
        // I-3: the IP is hashed (defense-in-depth — the transient key never
        // exposes a raw client IP at rest) using md5(), matching the enroll
        // limiter's cmwp_enroll_limit_<md5(ip)> for cross-limiter consistency.
        // The counter is a best-effort transient: NOT strictly atomic under
        // heavy concurrency, which is acceptable here because this is a
        // guessing-throttle on a 256-bit secret (a couple of races at the
        // boundary can't meaningfully help an attacker brute-force it).
        // CGPT_AUTH_MAX_FAILURES may differ from the enroll limiter's budget on
        // purpose: these are different credential classes — an enrollment code
        // is short-lived and single-use, whereas an API token is long-lived, so
        // each gets a failure budget tuned to its own risk profile.
        $ip = $this->get_client_ip();
        $limit_key = 'cmwp_cgpt_limit_' . md5($ip);
        $failures  = intval(get_transient($limit_key));
        if ($failures >= self::CGPT_AUTH_MAX_FAILURES) {
            $this->verification_error_code = 'connectmwp_cgpt_rate_limited';
            $this->cgpt_token_verified = false;
            return new WP_Error(
                'connectmwp_cgpt_rate_limited',
                $this->describe_verification_error('connectmwp_cgpt_rate_limited'),
                array('status' => 429)
            );
        }

        // [OAuth Phase 2] OAuth access-token branch. /mcp accepts OAuth 2.1
        // access tokens (cmwp_oat_) IN ADDITION to the cgpt API tokens
        // (cmwp_cgpt_), both as Authorization: Bearer. Branch by prefix: only a
        // cmwp_oat_-prefixed token is resolved here; everything else falls through
        // to the unchanged cgpt path below. On success we enforce RESOURCE-SERVER
        // checks the cgpt path doesn't have — audience (RFC 8707) and scope — then
        // bind the user with the SAME per-request cache + touch discipline. No
        // login session is created. A failed OAuth resolve counts against the same
        // IP limiter and returns the same 401 (+ WWW-Authenticate discovery
        // challenge) as a bad cgpt token, so an attacker can't distinguish them.
        if (strpos($token, self::OAUTH_ACCESS_TOKEN_PREFIX) === 0) {
            $oauth = $this->resolve_oauth_access_token($token);
            if ($oauth === false) {
                // Invalid / expired / wrong-type (e.g. a refresh token presented at
                // /mcp). Count against the IP limiter and 401.
                set_transient($limit_key, $failures + 1, self::CGPT_AUTH_LOCKOUT_SECONDS);
                $this->verification_error_code = 'connectmwp_oauth_invalid_token';
                $this->cgpt_token_verified = false;
                $this->oauth_emit_www_authenticate();
                return new WP_Error(
                    'connectmwp_oauth_invalid_token',
                    $this->describe_verification_error('connectmwp_oauth_invalid_token'),
                    array('status' => 401)
                );
            }

            $record = $oauth['record'];

            // RFC 8707 audience binding: the access token's audience MUST equal
            // this site's canonical /mcp URI. A token minted for a DIFFERENT
            // resource server must never be accepted here (cross-RS token reuse).
            if (!$this->oauth_resource_matches((string) $record['audience'])) {
                set_transient($limit_key, $failures + 1, self::CGPT_AUTH_LOCKOUT_SECONDS);
                $this->verification_error_code = 'connectmwp_oauth_invalid_token';
                $this->cgpt_token_verified = false;
                $this->oauth_emit_www_authenticate();
                return new WP_Error(
                    'connectmwp_oauth_invalid_token',
                    $this->describe_verification_error('connectmwp_oauth_invalid_token'),
                    array('status' => 401)
                );
            }

            // Scope: the token must carry the required 'connectmwp' scope.
            $scopes = $this->oauth_parse_scope((string) $record['scope']);
            if (!in_array('connectmwp', $scopes, true)) {
                set_transient($limit_key, $failures + 1, self::CGPT_AUTH_LOCKOUT_SECONDS);
                $this->verification_error_code = 'connectmwp_oauth_invalid_token';
                $this->cgpt_token_verified = false;
                $this->oauth_emit_www_authenticate();
                return new WP_Error(
                    'connectmwp_oauth_invalid_token',
                    $this->describe_verification_error('connectmwp_oauth_invalid_token'),
                    array('status' => 401)
                );
            }

            // Fail-closed: a token bound to no valid user is misconfigured.
            if ((int) ($record['bound_user_id'] ?? 0) <= 0) {
                $this->verification_error_code = 'connectmwp_oauth_unbound_token';
                $this->cgpt_token_verified = false;
                return new WP_Error(
                    'connectmwp_oauth_unbound_token',
                    $this->describe_verification_error('connectmwp_oauth_unbound_token'),
                    array('status' => 403)
                );
            }

            // Success: bind the user exactly as the cgpt path does (no session).
            // dispatch_action's capability checks then run as $this->bound_user_id.
            $this->bound_user_id       = (int) $record['bound_user_id'];
            $this->cgpt_bound_user_id  = $this->bound_user_id;
            $this->cgpt_token_verified = true;
            $this->touch_oauth_token($oauth['token_id'], $ip);
            return true;
        }

        // Resolve. The DAL pre-filters bad prefix/length cheaply and only
        // matches on a constant-time hash_equals against stored token hashes.
        $resolved = $this->resolve_cgpt_token($token);
        if ($resolved === false) {
            // Count this failed attempt against the IP. set_transient resets the
            // TTL each write — acceptable: a steady stream of bad guesses keeps
            // the lockout sliding, which is the desired anti-bruteforce behavior.
            set_transient($limit_key, $failures + 1, self::CGPT_AUTH_LOCKOUT_SECONDS);
            $this->verification_error_code = 'connectmwp_cgpt_invalid_token';
            $this->cgpt_token_verified = false;
            // Same discovery challenge on the invalid-token
            // 401 (still unauthenticated). Valid tokens never reach here.
            $this->oauth_emit_www_authenticate();
            return new WP_Error(
                'connectmwp_cgpt_invalid_token',
                $this->describe_verification_error('connectmwp_cgpt_invalid_token'),
                array('status' => 401)
            );
        }

        // Fail-closed guard: a resolved token with no valid bound user is
        // misconfigured (orphaned by a deleted user, or minted without a bind).
        // user_can(0, ...) already denies, but returning a generic Forbidden
        // would be confusing; surface an actionable diagnostic instead. Do NOT
        // touch the token and do NOT mark the verdict as a PASS.
        $record = $resolved['record'];
        if ((int) ($record['bound_user_id'] ?? 0) <= 0) {
            $this->verification_error_code = 'connectmwp_cgpt_unbound_token';
            $this->cgpt_token_verified = false;
            return new WP_Error(
                'connectmwp_cgpt_unbound_token',
                $this->describe_verification_error('connectmwp_cgpt_unbound_token'),
                array('status' => 403)
            );
        }

        // VR-6 / success: bind the user so check_* callbacks authorize via
        // user_can($this->bound_user_id, ...). No login session is created.
        // ($record was already fetched + bound-user-validated above.) Store the
        // resolved id in $cgpt_bound_user_id too, so a cached PASS on a second
        // permission_callback invocation can restore bound_user_id after the
        // I-1 entry reset.
        $this->bound_user_id      = (int) $record['bound_user_id'];
        $this->cgpt_bound_user_id = $this->bound_user_id;
        $this->cgpt_token_verified = true;

        // VR-4: touch last_used / last_ip ONLY after a successful resolve.
        $this->touch_cgpt_token($resolved['token_id'], $ip);

        return true;
    }

    /**
     * SSOT for the HTTP status that accompanies each connectmwp_cgpt_* failure
     * code. Used by verify_token_request()'s cached-failure branch to re-emit
     * the original status on a repeat permission_callback invocation; the
     * first-time failure paths pass the same status literals inline.
     */
    private function cgpt_status_for_code($code) {
        switch ($code) {
            case 'connectmwp_cgpt_missing_token':
            case 'connectmwp_cgpt_invalid_token':
            case 'connectmwp_oauth_invalid_token':
                return 401;
            case 'connectmwp_cgpt_rate_limited':
                return 429;
            case 'connectmwp_cgpt_insecure_transport':
            case 'connectmwp_cgpt_unbound_token':
            case 'connectmwp_oauth_unbound_token':
            default:
                return 403;
        }
    }

    private function is_replay_signature($sig_hash) {
        $option_name = 'cmwp_sig_' . $sig_hash;
        $now = time();
        $expiry = $now + self::REPLAY_TTL_SECONDS;

        // add_option is atomic in WordPress
        $added = add_option($option_name, $expiry, '', 'no');
        if (!$added) {
            return true;
        }

        // Clean up expired signatures with a 1% probability
        if (wp_rand(1, 100) === 42) {
            $this->prune_expired_signatures();
        }

        return false;
    }

    private function prune_expired_signatures() {
        global $wpdb;
        $now = time();
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(option_value AS UNSIGNED) < %d",
                'cmwp_sig_%',
                $now
            )
        );
    }

    // ========================================================================
    // Key storage DAL (SSOT) — T039
    //
    // The ONLY code permitted to touch key storage. Every handler/lookup routes
    // through these helpers; no call site reads/writes the raw option names
    // directly (enforced by the SSOT grep gate in _internal/verify/p7_test.sh).
    //
    // Atomicity model: each key is its own `connectmwp_key_<hex>` option row, so
    // a write to one key never rewrites another (closes the array read-modify-
    // write TOCTOU that could silently drop a concurrently-enrolled key). The
    // `connectmwp_key_index` option is a non-authoritative, self-healing list of
    // key ids used only for enumeration — the per-key rows are the source of
    // truth, so a stale/lost index can never delete a key.
    //
    // None of these establish a login session or call get_current_user_id().
    // ========================================================================

    /**
     * Map a key_id to its per-key option name. SSOT for the naming convention.
     * Strips the `cmwp_key_` id prefix so the option is `connectmwp_key_<hex>`
     * (avoids a confusing `connectmwp_key_cmwp_key_<hex>` and any collision with
     * the `cmwp_sig_` / `cmwp_enroll_limit_` families). Ids without the expected
     * prefix fall back to a deterministic hash so they still map stably.
     */
    private function key_option_name($key_id) {
        $key_id = (string) $key_id;
        $strip = self::KEY_PREFIX_STRIP;
        if (strpos($key_id, $strip) === 0) {
            $suffix = substr($key_id, strlen($strip));
        } else {
            // Defensive: any legacy/odd id still maps deterministically.
            $suffix = substr(hash('sha256', $key_id), 0, 32);
        }
        return self::KEY_OPTION_PREFIX . $suffix;
    }

    /**
     * Normalize a raw key record to the canonical six-field shape so every
     * consumer sees a stable structure regardless of source (per-key row, legacy
     * array, or a partial record). SSOT for the on-WP key schema.
     */
    private function normalize_key_record($raw) {
        if (!is_array($raw)) {
            $raw = [];
        }
        return [
            'public_key'    => isset($raw['public_key']) ? (string) $raw['public_key'] : '',
            'bound_user_id' => isset($raw['bound_user_id']) ? intval($raw['bound_user_id']) : 0,
            'label'         => isset($raw['label']) ? (string) $raw['label'] : '',
            'created'       => isset($raw['created']) ? (string) $raw['created'] : '',
            'last_used'     => isset($raw['last_used']) ? (string) $raw['last_used'] : '',
            'last_ip'       => isset($raw['last_ip']) ? (string) $raw['last_ip'] : '',
        ];
    }

    /**
     * Read a single key by id. Source of truth is the per-key option row; on a
     * miss we fall back to the retained legacy array (one-release backward read)
     * and lazily migrate that single entry forward so the new store warms on
     * read. Returns the normalized record, or false if the key does not exist.
     */
    private function get_key($key_id) {
        $row = get_option($this->key_option_name($key_id), null);
        if (is_array($row)) {
            return $this->normalize_key_record($row);
        }

        // Backward-read fallback: legacy monolithic array (retained one release).
        $legacy = get_option(self::LEGACY_KEYS_OPTION, []);
        if (is_array($legacy) && isset($legacy[$key_id]) && is_array($legacy[$key_id])) {
            $record = $this->normalize_key_record($legacy[$key_id]);
            // Lazy single-entry migration: warm the per-key store + index.
            // add_option is atomic — if a concurrent writer beat us, no harm.
            add_option($this->key_option_name($key_id), $record, '', 'no');
            $this->index_add($key_id);
            return $record;
        }

        return false;
    }

    /**
     * Atomic upsert of a single key row (touches only this key). Ensures the id
     * is present in the index.
     */
    private function save_key($key_id, array $record) {
        $record = $this->normalize_key_record($record);
        update_option($this->key_option_name($key_id), $record, 'no');
        $this->index_add($key_id);
        return true;
    }

    /**
     * Atomic create of a new key row. Uses add_option (fails if the row already
     * exists), so two concurrent enrollments of DIFFERENT keys both succeed on
     * their own rows — the headline race the array storage could not survive.
     * Returns true on create, false if a row for this id already existed.
     */
    private function add_key($key_id, array $record) {
        $record = $this->normalize_key_record($record);
        $created = add_option($this->key_option_name($key_id), $record, '', 'no');
        // Whether freshly created or already present, make sure the index lists it.
        $this->index_add($key_id);
        return (bool) $created;
    }

    /**
     * Update specific fields on a single key. Reads the freshest record
     * immediately before writing, so the read-modify-write window is per-key and
     * tiny — even two workers racing on the SAME key's last_used only produce a
     * last-writer-wins timestamp on THAT key, never a cross-key clobber.
     */
    private function update_key_fields($key_id, array $changes) {
        $record = $this->get_key($key_id);
        if ($record === false) {
            return false;
        }
        foreach ($changes as $field => $value) {
            $record[$field] = $value;
        }
        return $this->save_key($key_id, $record);
    }

    /**
     * Delete a single key: remove the per-key row, drop it from the index, and
     * (durability across the legacy fallback window) remove it from the legacy
     * array too — otherwise list_keys()'s legacy union could resurrect a revoked
     * key. Returns true if a per-key row or legacy entry was removed.
     */
    private function delete_key($key_id) {
        $removed = delete_option($this->key_option_name($key_id));
        $this->index_remove($key_id);

        // Remove from the retained legacy array if present so revoke is durable.
        $legacy = get_option(self::LEGACY_KEYS_OPTION, []);
        if (is_array($legacy) && isset($legacy[$key_id])) {
            unset($legacy[$key_id]);
            update_option(self::LEGACY_KEYS_OPTION, $legacy, 'no');
            $removed = true;
        }

        // Invalidate the latest-client poll hint if it pointed at the revoked key
        // (T058) — the poll then falls back to the authoritative list_keys().
        $hint = get_option(self::LATEST_CLIENT_OPTION);
        if (is_array($hint) && isset($hint['key_id']) && $hint['key_id'] === $key_id) {
            delete_option(self::LATEST_CLIENT_OPTION);
        }

        return (bool) $removed;
    }

    /**
     * Enumerate all keys as key_id => normalized_record. Single entry point for
     * the settings table (T043), pairing_status_handler and migration. Reads the
     * index, resolves each via get_key() (covers per-key rows + lazy legacy
     * migration), self-heals (drops index entries whose row is gone), and unions
     * any not-yet-migrated legacy ids (one-release fallback). De-dups by id.
     */
    private function list_keys() {
        $out = [];

        $index = get_option(self::KEY_INDEX_OPTION, []);
        if (is_array($index)) {
            $healed = [];
            foreach ($index as $key_id) {
                $rec = $this->get_key($key_id);
                if ($rec !== false) {
                    $out[$key_id] = $rec;
                    $healed[] = $key_id;
                }
            }
            // Self-heal: if the index referenced dead rows, prune them.
            if (count($healed) !== count($index)) {
                $this->write_key_index(array_values(array_unique($healed)));
            }
        }

        // Union any legacy-array ids not yet represented (backward-read window).
        $legacy = get_option(self::LEGACY_KEYS_OPTION, []);
        if (is_array($legacy)) {
            foreach ($legacy as $key_id => $raw) {
                if (!isset($out[$key_id])) {
                    $rec = $this->get_key($key_id); // warms + indexes via lazy migration
                    if ($rec !== false) {
                        $out[$key_id] = $rec;
                    }
                }
            }
        }

        return $out;
    }

    /**
     * Append a key_id to the index with a bounded optimistic retry. The index is
     * a non-authoritative hint; worst case it is briefly stale, which never
     * deletes a key because the per-key rows are independent.
     */
    private function index_add($key_id) {
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = get_option(self::KEY_INDEX_OPTION, []);
            if (!is_array($index)) {
                $index = [];
            }
            if (in_array($key_id, $index, true)) {
                return true; // already present
            }
            $next = $index;
            $next[] = $key_id;
            // update_option returns false when the stored value is unchanged;
            // since we appended, a false here means a concurrent writer changed
            // the row out from under us — re-read and retry.
            if (update_option(self::KEY_INDEX_OPTION, $next, 'no')) {
                return true;
            }
            // Re-read on next iteration to merge the concurrent change.
        }
        return false;
    }

    /**
     * Remove a key_id from the index with a bounded optimistic retry.
     */
    private function index_remove($key_id) {
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = get_option(self::KEY_INDEX_OPTION, []);
            if (!is_array($index)) {
                return true; // nothing to remove
            }
            if (!in_array($key_id, $index, true)) {
                return true; // already absent
            }
            $next = array_values(array_filter($index, function ($id) use ($key_id) {
                return $id !== $key_id;
            }));
            if (update_option(self::KEY_INDEX_OPTION, $next, 'no')) {
                return true;
            }
        }
        return false;
    }

    /**
     * Overwrite the index option wholesale. Used by self-heal and rebuild.
     */
    private function write_key_index(array $ids) {
        update_option(self::KEY_INDEX_OPTION, array_values(array_unique($ids)), 'no');
    }

    /**
     * Recovery path: rebuild the index from the authoritative per-key rows by
     * scanning wp_options for `connectmwp_key_%` (excluding the index option
     * itself). Used by migration to seed the index and available for support if
     * the index is ever lost. The `_` in the prefix is escaped so it matches a
     * literal underscore, not the LIKE single-char wildcard.
     */
    private function rebuild_key_index() {
        global $wpdb;
        $prefix = self::KEY_OPTION_PREFIX;
        // Escape LIKE metacharacters in the prefix (notably `_`).
        $like = $wpdb->esc_like($prefix) . '%';
        $names = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s AND option_name != %s",
                $like,
                self::KEY_INDEX_OPTION
            )
        );

        // Reconstruct key_ids from option names. The per-key suffix is the bare
        // hex of a `cmwp_key_<hex>` id, so the id is KEY_PREFIX_STRIP . suffix.
        $ids = [];
        if (is_array($names)) {
            foreach ($names as $name) {
                $suffix = substr($name, strlen($prefix));
                if ($suffix !== '' && $suffix !== false) {
                    $ids[] = self::KEY_PREFIX_STRIP . $suffix;
                }
            }
        }
        $this->write_key_index($ids);
        return $ids;
    }

    // ========================================================================
    // ChatGPT API-token DAL (T1)
    //
    // A parallel store for ChatGPT bearer tokens, mirroring the key DAL's atomic
    // per-row + self-healing-index design under the `connectmwp_cgpt_token_*`
    // namespace. ONLY the sha256 hash of a token is persisted; the plaintext is
    // produced once by mint_cgpt_token() and never stored or logged. Like the
    // key DAL, none of these establish a login session or call
    // get_current_user_id().
    // ========================================================================

    /**
     * Map a token_id to its per-token option name. SSOT for the naming
     * convention. Strips the `cmwp_cgpt_` id prefix so the option is
     * `connectmwp_cgpt_token_<hex>` (avoids a confusing doubled prefix and any
     * collision with the `connectmwp_key_` family). Ids without the expected
     * prefix fall back to a deterministic hash so they still map stably.
     */
    private function cgpt_token_option_name($token_id) {
        $token_id = (string) $token_id;
        $strip = self::CGPT_TOKEN_ID_PREFIX;
        if (strpos($token_id, $strip) === 0) {
            $suffix = substr($token_id, strlen($strip));
        } else {
            // Defensive: any odd id still maps deterministically. UNREACHABLE in
            // normal operation — mint_cgpt_token() always produces a well-formed
            // prefixed id. Note that an id reaching this branch would NOT round-trip
            // through rebuild_cgpt_token_index() (which reconstructs ids from the
            // prefix), so do NOT rely on this fallback for any persisted token.
            $suffix = substr(hash('sha256', $token_id), 0, 32);
        }
        return self::CGPT_TOKEN_OPTION_PREFIX . $suffix;
    }

    /**
     * Normalize a raw token record to the canonical six-field shape so every
     * consumer sees a stable structure regardless of source. SSOT for the on-WP
     * ChatGPT-token schema. NOTE: only `token_hash` (sha256 hex) is stored —
     * never the plaintext token.
     */
    private function normalize_cgpt_token_record($raw) {
        if (!is_array($raw)) {
            $raw = [];
        }
        return [
            'token_hash'    => isset($raw['token_hash']) ? (string) $raw['token_hash'] : '',
            'bound_user_id' => isset($raw['bound_user_id']) ? intval($raw['bound_user_id']) : 0,
            'label'         => isset($raw['label']) ? (string) $raw['label'] : '',
            'created'       => isset($raw['created']) ? (string) $raw['created'] : '',
            'last_used'     => isset($raw['last_used']) ? (string) $raw['last_used'] : '',
            'last_ip'       => isset($raw['last_ip']) ? (string) $raw['last_ip'] : '',
        ];
    }

    /**
     * Read a single ChatGPT token record by id. Source of truth is the per-token
     * option row. Returns the normalized record, or false if it does not exist.
     */
    private function get_cgpt_token($token_id) {
        $row = get_option($this->cgpt_token_option_name($token_id), null);
        if (is_array($row)) {
            return $this->normalize_cgpt_token_record($row);
        }
        return false;
    }

    /**
     * Atomic upsert of a single token row (touches only this token). Ensures the
     * id is present in the index.
     */
    private function save_cgpt_token($token_id, array $record) {
        $record = $this->normalize_cgpt_token_record($record);
        update_option($this->cgpt_token_option_name($token_id), $record, 'no');
        $this->cgpt_token_index_add($token_id);
        return true;
    }

    /**
     * Update specific fields on a single token. Reads the freshest record
     * immediately before writing, so the read-modify-write window is per-token
     * and tiny — two workers racing on the same token's last_used only produce a
     * last-writer-wins timestamp on THAT token, never a cross-token clobber.
     *
     * @internal Immutable fields (token_hash, bound_user_id, created) are dropped
     * from $changes before merging — they define the credential's identity and
     * binding and must never be mutated through this mutable-field path.
     */
    private function update_cgpt_token_fields($token_id, array $changes) {
        $record = $this->get_cgpt_token($token_id);
        if ($record === false) {
            return false;
        }
        // Footgun guard: never let a caller mutate the credential's identity or
        // binding via this path. These keys are silently ignored if present.
        unset($changes['token_hash'], $changes['bound_user_id'], $changes['created']);
        foreach ($changes as $field => $value) {
            $record[$field] = $value;
        }
        return $this->save_cgpt_token($token_id, $record);
    }

    /**
     * Mint a new ChatGPT API token. Generates a token_id and a SEPARATE
     * high-entropy secret, assembles the self-identifying plaintext
     * `cmwp_cgpt_<secret>`, persists ONLY its sha256 hash in a fresh atomic row,
     * and adds the id to the index. The returned `plaintext` is the ONLY moment
     * the token exists in cleartext — it is never stored or logged. Returns
     * ['token_id'=>..., 'plaintext'=>..., 'record'=>...] on success, or false if
     * the row could not be stored (id collision or transient DB failure) — in
     * that case NOTHING is added to the index and NO plaintext is handed back, so
     * the caller never receives a token that will never resolve.
     *
     * @return array|false
     */
    private function mint_cgpt_token($bound_user_id, $label) {
        // token_id is a NON-secret identifier (its only job is to name the option
        // row); 8 bytes is intentional and adequate for that. The actual credential
        // entropy lives entirely in the secret, governed by CGPT_TOKEN_SECRET_BYTES.
        $token_id = self::CGPT_TOKEN_ID_PREFIX . bin2hex(random_bytes(8));
        // Separate high-entropy secret (>= 32 random bytes), hex-encoded.
        $secret    = bin2hex(random_bytes(self::CGPT_TOKEN_SECRET_BYTES));
        // Self-identifying plaintext so it's recognizable in a connector UI.
        $plaintext = self::CGPT_TOKEN_ID_PREFIX . $secret;

        $record = $this->normalize_cgpt_token_record([
            'token_hash'    => hash('sha256', $plaintext),
            'bound_user_id' => intval($bound_user_id),
            'label'         => (string) $label,
            'created'       => current_time('mysql'),
            'last_used'     => '',
            'last_ip'       => '',
        ]);

        // Atomic per-token create. add_option returns false on an id collision
        // (the random row already exists) OR a transient DB failure. In either
        // case the row was NOT stored — so we must NOT index the id and must NOT
        // hand back a plaintext that would never resolve. Bail with false; the
        // caller treats that as "minting failed, try again".
        $stored = add_option($this->cgpt_token_option_name($token_id), $record, '', 'no');
        if (!$stored) {
            return false;
        }
        $this->cgpt_token_index_add($token_id);

        return [
            'token_id'  => $token_id,
            'plaintext' => $plaintext,
            'record'    => $record,
        ];
    }

    /**
     * Resolve a presented plaintext token to its record. Hashes the input once
     * and walks the candidate token rows comparing the stored hash with
     * hash_equals() (constant-time), so a match leaks no timing about WHICH token
     * matched beyond the unavoidable per-row lookup. Returns
     * ['token_id'=>..., 'record'=>...] on match, or false. Reads from the index
     * (self-healing via get_cgpt_token()).
     */
    private function resolve_cgpt_token($plaintext) {
        // Fast pre-filter: reject anything that cannot possibly be one of our
        // tokens BEFORE hashing or scanning the index. A well-formed plaintext is
        // `cmwp_cgpt_<hex>` where the hex is exactly CGPT_TOKEN_SECRET_BYTES bytes
        // hex-encoded (so 2 chars per byte). Centralizing the guard here keeps
        // obviously-invalid input from costing a full index scan.
        if (!is_string($plaintext) || $plaintext === '') {
            return false;
        }
        if (strpos($plaintext, self::CGPT_TOKEN_ID_PREFIX) !== 0) {
            return false;
        }
        $expected_len = strlen(self::CGPT_TOKEN_ID_PREFIX) + (self::CGPT_TOKEN_SECRET_BYTES * 2);
        if (strlen($plaintext) !== $expected_len) {
            return false;
        }
        $candidate_hash = hash('sha256', $plaintext);

        $index = get_option(self::CGPT_TOKEN_INDEX_OPTION, []);
        if (!is_array($index)) {
            return false;
        }

        foreach ($index as $token_id) {
            $record = $this->get_cgpt_token($token_id);
            if ($record === false) {
                continue;
            }
            $stored_hash = isset($record['token_hash']) ? (string) $record['token_hash'] : '';
            // Skip any candidate whose stored hash isn't a well-formed sha256 hex
            // (64 chars) — a malformed/blank hash can never be a real match, and
            // feeding it to hash_equals() against a 64-char candidate is wasted work.
            if (strlen($stored_hash) === 64 && hash_equals($stored_hash, $candidate_hash)) {
                return [
                    'token_id' => $token_id,
                    'record'   => $record,
                ];
            }
        }

        return false;
    }

    /**
     * Enumerate all ChatGPT tokens as token_id => normalized_record. Reads the
     * index, resolves each via get_cgpt_token(), and self-heals (drops index
     * entries whose row is gone), mirroring list_keys(). There is no legacy
     * fallback — this store is new in T1.
     */
    private function list_cgpt_tokens() {
        $out = [];

        $index = get_option(self::CGPT_TOKEN_INDEX_OPTION, []);
        if (is_array($index)) {
            $healed = [];
            foreach ($index as $token_id) {
                $rec = $this->get_cgpt_token($token_id);
                if ($rec !== false) {
                    $out[$token_id] = $rec;
                    $healed[] = $token_id;
                }
            }
            // Self-heal: if the index referenced dead rows, prune them.
            if (count($healed) !== count($index)) {
                $this->write_cgpt_token_index(array_values(array_unique($healed)));
            }
        }

        return $out;
    }

    /**
     * Delete a single token: immediate revoke. Removes the per-token row and
     * drops it from the index. Returns true if a row was removed.
     */
    private function delete_cgpt_token($token_id) {
        $removed = delete_option($this->cgpt_token_option_name($token_id));
        $this->cgpt_token_index_remove($token_id);
        return (bool) $removed;
    }

    /**
     * Throttled (~60s) last-used / last-ip touch for a token. Mutates ONLY this
     * token's row (atomic), throttled exactly like update_key_last_used().
     */
    private function touch_cgpt_token($token_id, $ip) {
        $record = $this->get_cgpt_token($token_id);
        if ($record === false) {
            return;
        }
        $last_used_str = $record['last_used'] ?? '';
        $last_used_time = !empty($last_used_str) && $last_used_str !== 'Never' ? strtotime($last_used_str) : 0;
        if (time() - $last_used_time > self::LAST_USED_THROTTLE_SECONDS) {
            $this->update_cgpt_token_fields($token_id, [
                'last_used' => current_time('mysql'),
                'last_ip'   => (string) $ip,
            ]);
        }
    }

    /**
     * Append a token_id to the index with a bounded optimistic retry. The index
     * is a non-authoritative hint; worst case it is briefly stale, which never
     * deletes a token because the per-token rows are independent. Mirrors
     * index_add().
     */
    private function cgpt_token_index_add($token_id) {
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = get_option(self::CGPT_TOKEN_INDEX_OPTION, []);
            if (!is_array($index)) {
                $index = [];
            }
            if (in_array($token_id, $index, true)) {
                return true; // already present
            }
            $next = $index;
            $next[] = $token_id;
            // update_option returns false when the stored value is unchanged;
            // since we appended, a false here means a concurrent writer changed
            // the row out from under us — re-read and retry.
            if (update_option(self::CGPT_TOKEN_INDEX_OPTION, $next, 'no')) {
                return true;
            }
            // Re-read on next iteration to merge the concurrent change.
        }
        return false;
    }

    /**
     * Remove a token_id from the index with a bounded optimistic retry. Mirrors
     * index_remove().
     */
    private function cgpt_token_index_remove($token_id) {
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = get_option(self::CGPT_TOKEN_INDEX_OPTION, []);
            if (!is_array($index)) {
                return true; // nothing to remove
            }
            if (!in_array($token_id, $index, true)) {
                return true; // already absent
            }
            $next = array_values(array_filter($index, function ($id) use ($token_id) {
                return $id !== $token_id;
            }));
            if (update_option(self::CGPT_TOKEN_INDEX_OPTION, $next, 'no')) {
                return true;
            }
        }
        return false;
    }

    /**
     * Overwrite the token index option wholesale. Used by self-heal and rebuild.
     * Mirrors write_key_index().
     */
    private function write_cgpt_token_index(array $ids) {
        update_option(self::CGPT_TOKEN_INDEX_OPTION, array_values(array_unique($ids)), 'no');
    }

    /**
     * Recovery path: rebuild the token index from the authoritative per-token
     * rows by scanning wp_options for `connectmwp_cgpt_token_%` (excluding the
     * index option itself). Mirrors rebuild_key_index(). The `_` in the prefix is
     * escaped so it matches a literal underscore, not the LIKE single-char
     * wildcard.
     */
    private function rebuild_cgpt_token_index() {
        global $wpdb;
        $prefix = self::CGPT_TOKEN_OPTION_PREFIX;
        // Escape LIKE metacharacters in the prefix (notably `_`).
        $like = $wpdb->esc_like($prefix) . '%';
        $names = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s AND option_name != %s",
                $like,
                self::CGPT_TOKEN_INDEX_OPTION
            )
        );

        // Reconstruct token_ids from option names. The per-token suffix is the
        // bare hex of a `cmwp_cgpt_<hex>` id, so the id is
        // CGPT_TOKEN_ID_PREFIX . suffix.
        $ids = [];
        if (is_array($names)) {
            foreach ($names as $name) {
                $suffix = substr($name, strlen($prefix));
                if ($suffix !== '' && $suffix !== false) {
                    $ids[] = self::CGPT_TOKEN_ID_PREFIX . $suffix;
                }
            }
        }
        $this->write_cgpt_token_index($ids);
        return $ids;
    }

    // ========================================================================
    // [OAuth Phase 1] Authorization-code DAL.
    //
    // Mirrors the cgpt-token DAL: one option row per code, autoload `no`, plus a
    // non-authoritative, self-healing index. ONLY the sha256 hash of the code is
    // persisted — the plaintext code exists exactly once, as the return of
    // mint_oauth_code(), and is never stored or logged. Codes are short-TTL
    // (OAUTH_CODE_TTL_SECONDS) and SINGLE-USE: consume_oauth_code() looks up by
    // hash in constant time and ATOMICALLY deletes the row before returning the
    // grant, so a second exchange of the same code fails. Phase 2's /oauth/token
    // calls consume_oauth_code().
    // ========================================================================

    /** [OAuth Phase 1] Map a code_id to its per-code option name. */
    private function oauth_code_option_name($code_id) {
        $code_id = (string) $code_id;
        $strip = self::OAUTH_CODE_ID_PREFIX;
        if (strpos($code_id, $strip) === 0) {
            $suffix = substr($code_id, strlen($strip));
        } else {
            $suffix = substr(hash('sha256', $code_id), 0, 32);
        }
        return self::OAUTH_CODE_OPTION_PREFIX . $suffix;
    }

    /**
     * [OAuth Phase 1] Normalize a stored auth-code grant to its canonical shape.
     * SSOT for the on-WP auth-code schema. Only `code_hash` (sha256 hex) is the
     * credential material; the rest is the bound grant.
     */
    private function normalize_oauth_code_record($raw) {
        if (!is_array($raw)) {
            $raw = [];
        }
        return [
            'code_hash'             => isset($raw['code_hash']) ? (string) $raw['code_hash'] : '',
            'client_id'             => isset($raw['client_id']) ? (string) $raw['client_id'] : '',
            'redirect_uri'          => isset($raw['redirect_uri']) ? (string) $raw['redirect_uri'] : '',
            'code_challenge'        => isset($raw['code_challenge']) ? (string) $raw['code_challenge'] : '',
            'code_challenge_method' => isset($raw['code_challenge_method']) ? (string) $raw['code_challenge_method'] : '',
            'resource'              => isset($raw['resource']) ? (string) $raw['resource'] : '',
            'bound_user_id'         => isset($raw['bound_user_id']) ? intval($raw['bound_user_id']) : 0,
            'scope'                 => isset($raw['scope']) ? (string) $raw['scope'] : '',
            'created'               => isset($raw['created']) ? intval($raw['created']) : 0,
        ];
    }

    /**
     * [OAuth Phase 1] Mint a single-use authorization code bound to a grant.
     * Generates a code_id (row name) plus a SEPARATE high-entropy secret, returns
     * the opaque plaintext code (the only time it exists), and persists ONLY its
     * sha256 hash plus the grant fields with a creation timestamp. Returns the
     * plaintext code string on success, or WP_Error on a storage failure (so the
     * caller never hands back a code that cannot be consumed).
     *
     * @param array $grant client_id, redirect_uri, code_challenge,
     *                     code_challenge_method, resource, bound_user_id, scope.
     * @return string|WP_Error
     */
    private function mint_oauth_code(array $grant) {
        $code_id = self::OAUTH_CODE_ID_PREFIX . bin2hex(random_bytes(8));
        $secret  = bin2hex(random_bytes(self::OAUTH_CODE_SECRET_BYTES));
        // Opaque code returned to the client. Prefixed so it's recognizable, but
        // the prefix carries no authority — the secret is the entropy.
        $plaintext = self::OAUTH_CODE_ID_PREFIX . $secret;

        // Soft cap on the number of live code rows (mostly expired). If we are at
        // the cap, opportunistically prune expired rows before refusing.
        $this->oauth_prune_expired_codes();

        // Enforce the hard cap AFTER pruning: if still at/over MAX_OAUTH_CODES,
        // refuse rather than let the code store grow unbounded. The caller maps
        // this transient-capacity error to a temporarily_unavailable redirect.
        $idx = $this->oauth_normalize_index(get_option(self::OAUTH_CODE_INDEX_OPTION, []));
        if (count($idx) >= self::MAX_OAUTH_CODES) {
            return new WP_Error('cmwp_oauth_code_capacity', __('Too many pending authorization codes; try again shortly.', 'connectmwp'));
        }

        $record = $this->normalize_oauth_code_record([
            'code_hash'             => hash('sha256', $plaintext),
            'client_id'             => isset($grant['client_id']) ? (string) $grant['client_id'] : '',
            'redirect_uri'          => isset($grant['redirect_uri']) ? (string) $grant['redirect_uri'] : '',
            'code_challenge'        => isset($grant['code_challenge']) ? (string) $grant['code_challenge'] : '',
            'code_challenge_method' => isset($grant['code_challenge_method']) ? (string) $grant['code_challenge_method'] : '',
            'resource'              => isset($grant['resource']) ? (string) $grant['resource'] : '',
            'bound_user_id'         => isset($grant['bound_user_id']) ? intval($grant['bound_user_id']) : 0,
            'scope'                 => isset($grant['scope']) ? (string) $grant['scope'] : '',
            'created'               => time(),
        ]);

        // Atomic per-code create. add_option returns false on id collision or a
        // transient DB failure — in either case the row was NOT stored, so do not
        // index it and do not hand back a code that will never resolve.
        $stored = add_option($this->oauth_code_option_name($code_id), $record, '', 'no');
        if (!$stored) {
            return new WP_Error('cmwp_oauth_code_store', __('Could not store the authorization code.', 'connectmwp'));
        }
        // Index carries the absolute expiry so prune never re-reads this row.
        $this->oauth_code_index_add($code_id, $record['created'] + self::OAUTH_CODE_TTL_SECONDS);

        return $plaintext;
    }

    /**
     * [OAuth Phase 1] Consume a presented plaintext authorization code: validate
     * its structure, find the row by sha256 hash in constant time, ATOMICALLY
     * delete it (single-use), enforce the TTL, and return the bound grant. A
     * second call with the same code returns false because the row is gone.
     * Phase 2's token endpoint is the only intended caller.
     *
     * @param string $code
     * @return array|false The normalized grant on success, false otherwise.
     */
    private function consume_oauth_code($code) {
        if (!is_string($code) || $code === '') {
            return false;
        }
        if (strpos($code, self::OAUTH_CODE_ID_PREFIX) !== 0) {
            return false;
        }
        $expected_len = strlen(self::OAUTH_CODE_ID_PREFIX) + (self::OAUTH_CODE_SECRET_BYTES * 2);
        if (strlen($code) !== $expected_len) {
            return false;
        }
        $candidate_hash = hash('sha256', $code);

        // Shape-agnostic: array_keys() yields the code_ids whether the option is
        // the new id=>expiry map or the legacy flat list.
        $index = $this->oauth_normalize_index(get_option(self::OAUTH_CODE_INDEX_OPTION, []));

        foreach (array_keys($index) as $code_id) {
            $row = get_option($this->oauth_code_option_name($code_id), null);
            if (!is_array($row)) {
                continue;
            }
            $record = $this->normalize_oauth_code_record($row);
            $stored_hash = $record['code_hash'];
            if (strlen($stored_hash) !== 64 || !hash_equals($stored_hash, $candidate_hash)) {
                continue;
            }

            // Match. ATOMIC single-use: delete BEFORE any further use. delete_option
            // returns true only for the worker that actually removed the row, so a
            // concurrent double-exchange yields at most one success.
            $deleted = delete_option($this->oauth_code_option_name($code_id));
            $this->oauth_code_index_remove($code_id);
            if (!$deleted) {
                return false; // lost the race — treat as already consumed
            }

            // TTL enforcement AFTER consumption (the code is now spent either way).
            if ($record['created'] <= 0 || (time() - $record['created']) > self::OAUTH_CODE_TTL_SECONDS) {
                return false; // expired
            }

            return $record;
        }

        return false;
    }

    /**
     * [OAuth Phase 1/2] Normalize a code/token index option to its canonical
     * shape: an associative map `id (string) => expiry (int, unix seconds)`.
     *
     * Tolerates the LEGACY flat-list shape `[0 => id, 1 => id, …]` written by
     * plugins <= 2.3.6 (before expiry-in-index, T082): such entries come back
     * with a placeholder expiry of 0 ("unknown"), and the prune/add/remove/list
     * paths backfill the real expiry and rewrite the option in the new shape on
     * first touch — so a site self-migrates with no discrete migration step. The
     * discriminator is the VALUE type: an int value is a new-shape expiry (its
     * key is the id); a string value is a legacy id (its key is a meaningless
     * list index). This keeps every reader shape-agnostic via array_keys().
     */
    private function oauth_normalize_index($raw) {
        $out = [];
        if (!is_array($raw)) {
            return $out;
        }
        foreach ($raw as $k => $v) {
            if (is_string($k) && $k !== '' && is_int($v)) {
                $out[$k] = $v;            // new shape: id => expiry
            } elseif (is_string($v) && $v !== '') {
                if (!isset($out[$v])) {
                    $out[$v] = 0;         // legacy flat entry: id, expiry unknown
                }
            }
        }
        return $out;
    }

    /**
     * [OAuth Phase 1] Upsert a code_id => expiry entry into the index (bounded
     * optimistic retry). The absolute expiry (unix) is carried IN the index so
     * oauth_prune_expired_codes() can judge liveness without reading the per-code
     * row (the T082 fix). Idempotent: a re-add with the same expiry is a no-op.
     */
    private function oauth_code_index_add($code_id, $expiry) {
        $expiry = intval($expiry);
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = $this->oauth_normalize_index(get_option(self::OAUTH_CODE_INDEX_OPTION, []));
            if (isset($index[$code_id]) && $index[$code_id] === $expiry) {
                return true;
            }
            $index[$code_id] = $expiry;
            if (update_option(self::OAUTH_CODE_INDEX_OPTION, $index, 'no')) {
                return true;
            }
        }
        return false;
    }

    /** [OAuth Phase 1] Remove a code_id from the index (bounded optimistic retry). */
    private function oauth_code_index_remove($code_id) {
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = $this->oauth_normalize_index(get_option(self::OAUTH_CODE_INDEX_OPTION, []));
            if (!isset($index[$code_id])) {
                return true;
            }
            unset($index[$code_id]);
            if (update_option(self::OAUTH_CODE_INDEX_OPTION, $index, 'no')) {
                return true;
            }
        }
        return false;
    }

    /**
     * [OAuth Phase 1] Best-effort prune of expired auth-code rows. Keeps the
     * store from accumulating dead rows (codes are TTL'd and single-use, but a
     * never-exchanged code would otherwise linger).
     *
     * T082: the expiry now lives IN the index (id => expiry), so the common case
     * reads ONLY the single index option — no per-row get_option(). The one
     * exception is a LEGACY entry (expiry 0, written before this release): its
     * row is read once to backfill the real expiry, then it is migrated into the
     * new shape. After the first prune cycle the whole index is O(1) to scan.
     * (Tradeoff vs the old version: a dead-but-unexpired row — i.e. one whose
     * delete_option succeeded but whose index_remove lost its retry race — now
     * lingers until its own expiry instead of being swept here; list_oauth_tokens
     * still self-heals the admin view. Codes' 120s TTL makes this immaterial.)
     */
    private function oauth_prune_expired_codes() {
        $raw = get_option(self::OAUTH_CODE_INDEX_OPTION, []);
        if (!is_array($raw) || empty($raw)) {
            return;
        }
        $index   = $this->oauth_normalize_index($raw);
        $now     = time();
        $next    = [];
        $changed = false;
        foreach ($index as $code_id => $expiry) {
            if ($expiry <= 0) {
                // Legacy entry: read the row ONCE to backfill its expiry, then
                // migrate to the new shape. Only un-migrated entries pay this.
                $changed = true;
                $row = get_option($this->oauth_code_option_name($code_id), null);
                if (is_array($row)) {
                    $rec    = $this->normalize_oauth_code_record($row);
                    $expiry = ($rec['created'] > 0) ? ($rec['created'] + self::OAUTH_CODE_TTL_SECONDS) : 0;
                } else {
                    $expiry = 0; // row already gone — fall through to drop
                }
            }
            if ($expiry <= 0 || $now >= $expiry) {
                delete_option($this->oauth_code_option_name($code_id));
                $changed = true;
                continue;
            }
            $next[$code_id] = $expiry;
        }
        if ($changed) {
            update_option(self::OAUTH_CODE_INDEX_OPTION, $next, 'no');
        }
    }

    // ========================================================================
    // [OAuth Phase 2] Access/refresh-token DAL.
    //
    // Mirrors the cgpt-token + auth-code DALs: one option row per token, autoload
    // `no`, plus a non-authoritative, self-healing, capped index. ONLY the sha256
    // hash of a token is persisted — the plaintext exists exactly once (return of
    // mint_oauth_tokens / rotate_oauth_refresh_token) and is never stored or
    // logged. Records carry the bound user, scope, audience (the canonical /mcp
    // URI — RFC 8707), client_id, token `type` (access|refresh), an absolute
    // `expires` (unix), and a `family` id linking an access token to the refresh
    // token it was issued alongside (so a refresh rotation can revoke the prior
    // access token of the same family and a detected refresh-reuse can nuke the
    // whole family). resolve_oauth_access_token() is the resource-server entry
    // point; rotate_oauth_refresh_token() implements OAuth 2.1 refresh rotation.
    // ========================================================================

    /** [OAuth Phase 2] Map a token_id to its per-token option name. */
    private function oauth_token_option_name($token_id) {
        $token_id = (string) $token_id;
        $strip = self::OAUTH_TOKEN_ID_PREFIX;
        if (strpos($token_id, $strip) === 0) {
            $suffix = substr($token_id, strlen($strip));
        } else {
            // Defensive: any odd id still maps deterministically. UNREACHABLE in
            // normal operation — mint always produces a well-formed prefixed id.
            $suffix = substr(hash('sha256', $token_id), 0, 32);
        }
        return self::OAUTH_TOKEN_OPTION_PREFIX . $suffix;
    }

    /**
     * [OAuth Phase 2] Normalize a stored OAuth-token record to its canonical
     * shape. SSOT for the on-WP access/refresh-token schema. Only `token_hash`
     * (sha256 hex) is credential material; the rest binds the grant.
     */
    private function normalize_oauth_token_record($raw) {
        if (!is_array($raw)) {
            $raw = [];
        }
        $type = isset($raw['type']) ? (string) $raw['type'] : '';
        if ($type !== 'access' && $type !== 'refresh') {
            $type = '';
        }
        return [
            'token_hash'    => isset($raw['token_hash']) ? (string) $raw['token_hash'] : '',
            'type'          => $type,
            'bound_user_id' => isset($raw['bound_user_id']) ? intval($raw['bound_user_id']) : 0,
            'scope'         => isset($raw['scope']) ? (string) $raw['scope'] : '',
            'audience'      => isset($raw['audience']) ? (string) $raw['audience'] : '',
            'client_id'     => isset($raw['client_id']) ? (string) $raw['client_id'] : '',
            'family'        => isset($raw['family']) ? (string) $raw['family'] : '',
            'expires'       => isset($raw['expires']) ? intval($raw['expires']) : 0,
            'created'       => isset($raw['created']) ? intval($raw['created']) : 0,
            'last_used'     => isset($raw['last_used']) ? intval($raw['last_used']) : 0,
            'last_ip'       => isset($raw['last_ip']) ? (string) $raw['last_ip'] : '',
        ];
    }

    /** [OAuth Phase 2] Read a single token row by id (normalized) or false. */
    private function get_oauth_token($token_id) {
        $row = get_option($this->oauth_token_option_name($token_id), null);
        if (is_array($row)) {
            return $this->normalize_oauth_token_record($row);
        }
        return false;
    }

    /**
     * [OAuth Phase 2] Persist ONE token row (sha256 hash of the plaintext +
     * metadata) and index it. Returns the token_id on success, or false if the
     * atomic create failed (id collision or transient DB error) — in which case
     * NOTHING is indexed and the caller must NOT hand back the plaintext.
     *
     * @param string $plaintext The full plaintext token (prefixed). Hashed here.
     * @param array  $meta      type, bound_user_id, scope, audience, client_id,
     *                          family, expires.
     * @return string|false token_id
     */
    private function store_oauth_token($plaintext, array $meta) {
        $token_id = self::OAUTH_TOKEN_ID_PREFIX . bin2hex(random_bytes(8));
        $record = $this->normalize_oauth_token_record([
            'token_hash'    => hash('sha256', $plaintext),
            'type'          => isset($meta['type']) ? $meta['type'] : '',
            'bound_user_id' => isset($meta['bound_user_id']) ? intval($meta['bound_user_id']) : 0,
            'scope'         => isset($meta['scope']) ? (string) $meta['scope'] : '',
            'audience'      => isset($meta['audience']) ? (string) $meta['audience'] : '',
            'client_id'     => isset($meta['client_id']) ? (string) $meta['client_id'] : '',
            'family'        => isset($meta['family']) ? (string) $meta['family'] : '',
            'expires'       => isset($meta['expires']) ? intval($meta['expires']) : 0,
            'created'       => time(),
            'last_used'     => 0,
            'last_ip'       => '',
        ]);

        // Atomic per-token create. add_option returns false on id collision or a
        // transient DB failure — in either case the row was NOT stored, so do not
        // index it and do not hand back a token that will never resolve.
        $stored = add_option($this->oauth_token_option_name($token_id), $record, '', 'no');
        if (!$stored) {
            return false;
        }
        // Index carries the absolute expiry so prune never re-reads this row.
        $this->oauth_token_index_add($token_id, $record['expires']);
        return $token_id;
    }

    /**
     * [OAuth Phase 2] Issue an access + refresh token pair for a redeemed grant.
     * Both share a fresh `family` id so a later refresh rotation (or a detected
     * reuse) can target the lineage. Returns the plaintexts + expires_in, or false
     * if either row could not be stored (in which case any partially-stored row is
     * cleaned up so no orphan credential lingers).
     *
     * @param array $grant Redeemed auth-code grant (bound_user_id, scope,
     *                     resource, client_id). `resource` becomes the token
     *                     `audience` (RFC 8707).
     * @return array|false { access_token, refresh_token, expires_in,
     *                       token_type, scope }
     */
    private function mint_oauth_tokens(array $grant) {
        $this->oauth_prune_expired_tokens();

        // Hard cap AFTER pruning: refuse rather than grow the token store
        // unbounded. Each issuance adds two rows.
        $idx = $this->oauth_normalize_index(get_option(self::OAUTH_TOKEN_INDEX_OPTION, []));
        if ((count($idx) + 2) > self::MAX_OAUTH_TOKENS) {
            return false;
        }

        $bound_user_id = isset($grant['bound_user_id']) ? intval($grant['bound_user_id']) : 0;
        $scope         = isset($grant['scope']) ? (string) $grant['scope'] : '';
        // Audience is the resource the grant was bound to. The grant's `resource`
        // is the canonical /mcp URI (set by the authorize handler); fall back to
        // the live canonical URI if somehow absent.
        $audience      = isset($grant['resource']) && $grant['resource'] !== ''
            ? (string) $grant['resource']
            : $this->oauth_canonical_mcp_uri();
        $client_id     = isset($grant['client_id']) ? (string) $grant['client_id'] : '';

        $family = bin2hex(random_bytes(16));
        $now    = time();

        $access_plain  = self::OAUTH_ACCESS_TOKEN_PREFIX . bin2hex(random_bytes(self::OAUTH_TOKEN_SECRET_BYTES));
        $refresh_plain = self::OAUTH_REFRESH_TOKEN_PREFIX . bin2hex(random_bytes(self::OAUTH_TOKEN_SECRET_BYTES));

        $access_id = $this->store_oauth_token($access_plain, [
            'type'          => 'access',
            'bound_user_id' => $bound_user_id,
            'scope'         => $scope,
            'audience'      => $audience,
            'client_id'     => $client_id,
            'family'        => $family,
            'expires'       => $now + self::OAUTH_ACCESS_TOKEN_TTL,
        ]);
        if ($access_id === false) {
            return false;
        }

        $refresh_id = $this->store_oauth_token($refresh_plain, [
            'type'          => 'refresh',
            'bound_user_id' => $bound_user_id,
            'scope'         => $scope,
            'audience'      => $audience,
            'client_id'     => $client_id,
            'family'        => $family,
            'expires'       => $now + self::OAUTH_REFRESH_TOKEN_TTL,
        ]);
        if ($refresh_id === false) {
            // Roll back the access token so we never leave an orphaned half-pair.
            $this->delete_oauth_token($access_id);
            return false;
        }

        return [
            'access_token'  => $access_plain,
            'refresh_token' => $refresh_plain,
            'token_type'    => 'Bearer',
            'expires_in'    => self::OAUTH_ACCESS_TOKEN_TTL,
            'scope'         => $scope,
        ];
    }

    /**
     * [OAuth Phase 2] Resolve a presented plaintext ACCESS token to its record.
     * Prefix/length pre-filter, constant-time hash lookup over the index, and a
     * hard reject of anything that is not an unexpired access token. Returns
     * ['token_id'=>..., 'record'=>...] on success, or false. The resource server
     * (verify_token_request) is the only intended caller; it then enforces
     * audience + scope itself.
     */
    private function resolve_oauth_access_token($plaintext) {
        if (!is_string($plaintext) || $plaintext === '') {
            return false;
        }
        if (strpos($plaintext, self::OAUTH_ACCESS_TOKEN_PREFIX) !== 0) {
            return false;
        }
        $expected_len = strlen(self::OAUTH_ACCESS_TOKEN_PREFIX) + (self::OAUTH_TOKEN_SECRET_BYTES * 2);
        if (strlen($plaintext) !== $expected_len) {
            return false;
        }
        $candidate_hash = hash('sha256', $plaintext);

        // Shape-agnostic: array_keys() yields the token_ids whether the option is
        // the new id=>expiry map or the legacy flat list.
        $index = $this->oauth_normalize_index(get_option(self::OAUTH_TOKEN_INDEX_OPTION, []));

        foreach (array_keys($index) as $token_id) {
            $record = $this->get_oauth_token($token_id);
            if ($record === false) {
                continue;
            }
            $stored_hash = $record['token_hash'];
            if (strlen($stored_hash) !== 64 || !hash_equals($stored_hash, $candidate_hash)) {
                continue;
            }
            // Hash matched. Enforce type + expiry. A refresh token presented as a
            // bearer at /mcp must NOT authenticate, even though its hash lives in
            // the same store.
            if ($record['type'] !== 'access') {
                return false;
            }
            if ($record['expires'] <= 0 || time() >= $record['expires']) {
                return false; // expired
            }
            return [
                'token_id' => $token_id,
                'record'   => $record,
            ];
        }

        return false;
    }

    /**
     * [OAuth Phase 2] NON-consuming peek of a presented refresh token (I-2).
     * Resolves the plaintext to its stored record and validates prefix/length,
     * type ('refresh'), and expiry — but does NOT delete the row. Used by the
     * token endpoint to gate the no-widen scope/audience check BEFORE spending
     * (rotating) the token, so an innocent/mistaken widen request can no longer
     * permanently destroy a client's refresh token. Single-use is still enforced
     * solely by rotate_oauth_refresh_token's atomic delete; this peek must never
     * mutate state. Returns ['token_id'=>..., 'record'=>...] or false.
     */
    private function peek_oauth_refresh_token($plaintext) {
        if (!is_string($plaintext) || $plaintext === '') {
            return false;
        }
        if (strpos($plaintext, self::OAUTH_REFRESH_TOKEN_PREFIX) !== 0) {
            return false;
        }
        $expected_len = strlen(self::OAUTH_REFRESH_TOKEN_PREFIX) + (self::OAUTH_TOKEN_SECRET_BYTES * 2);
        if (strlen($plaintext) !== $expected_len) {
            return false;
        }
        $candidate_hash = hash('sha256', $plaintext);

        // Shape-agnostic: array_keys() yields the token_ids whether the option is
        // the new id=>expiry map or the legacy flat list.
        $index = $this->oauth_normalize_index(get_option(self::OAUTH_TOKEN_INDEX_OPTION, []));

        foreach (array_keys($index) as $token_id) {
            $record = $this->get_oauth_token($token_id);
            if ($record === false) {
                continue;
            }
            $stored_hash = $record['token_hash'];
            if (strlen($stored_hash) !== 64 || !hash_equals($stored_hash, $candidate_hash)) {
                continue;
            }
            // Matched a row. It MUST be a refresh token and unexpired. (No delete —
            // this is a read-only peek; rotate enforces single-use.)
            if ($record['type'] !== 'refresh') {
                return false;
            }
            if ($record['expires'] <= 0 || time() >= $record['expires']) {
                return false; // expired refresh token
            }
            return [
                'token_id' => $token_id,
                'record'   => $record,
            ];
        }

        return false;
    }

    /**
     * [OAuth Phase 2] Validate + ROTATE a presented refresh token. OAuth 2.1
     * requires refresh rotation for public clients: on each use we invalidate the
     * presented refresh token and issue a NEW access+refresh pair bound to the
     * SAME user/scope/audience/client. On reuse of an already-rotated token (its
     * row is gone), we cannot match it, so the call fails closed — and if the
     * presented token DOES still match but belongs to a family we've decided to
     * burn, we revoke the whole family. Returns the new plaintext pair (same shape
     * as mint_oauth_tokens) or false.
     *
     * NOTE: scope/audience are taken from the stored refresh record and are NEVER
     * widened here — the token endpoint additionally rejects any request that
     * tries to broaden them.
     */
    private function rotate_oauth_refresh_token($plaintext) {
        if (!is_string($plaintext) || $plaintext === '') {
            return false;
        }
        if (strpos($plaintext, self::OAUTH_REFRESH_TOKEN_PREFIX) !== 0) {
            return false;
        }
        $expected_len = strlen(self::OAUTH_REFRESH_TOKEN_PREFIX) + (self::OAUTH_TOKEN_SECRET_BYTES * 2);
        if (strlen($plaintext) !== $expected_len) {
            return false;
        }
        $candidate_hash = hash('sha256', $plaintext);

        // Shape-agnostic: array_keys() yields the token_ids whether the option is
        // the new id=>expiry map or the legacy flat list.
        $index = $this->oauth_normalize_index(get_option(self::OAUTH_TOKEN_INDEX_OPTION, []));

        foreach (array_keys($index) as $token_id) {
            $record = $this->get_oauth_token($token_id);
            if ($record === false) {
                continue;
            }
            $stored_hash = $record['token_hash'];
            if (strlen($stored_hash) !== 64 || !hash_equals($stored_hash, $candidate_hash)) {
                continue;
            }

            // Matched a row. It MUST be a refresh token.
            if ($record['type'] !== 'refresh') {
                return false;
            }

            // ATOMIC single-use: delete the presented refresh token BEFORE issuing
            // a new pair. delete_option returns true only for the worker that
            // actually removed the row, so a concurrent double-rotate yields at
            // most one success (the loser fails closed).
            $deleted = delete_option($this->oauth_token_option_name($token_id));
            $this->oauth_token_index_remove($token_id);
            if (!$deleted) {
                return false; // lost the race — treat as already rotated
            }

            // Expiry check AFTER consumption (the token is spent either way).
            if ($record['expires'] <= 0 || time() >= $record['expires']) {
                return false; // expired refresh token
            }

            // Issue a fresh pair bound to the SAME grant. A new family id is used
            // so each lineage stays independent. Scope/audience carried verbatim
            // from the stored record — never widened.
            return $this->mint_oauth_tokens([
                'bound_user_id' => $record['bound_user_id'],
                'scope'         => $record['scope'],
                'resource'      => $record['audience'],
                'client_id'     => $record['client_id'],
            ]);
        }

        // No matching live row. Either a forged token or a REUSE of an already
        // rotated refresh token (the row was deleted on the prior rotation). Fail
        // closed. (We cannot revoke the family here because, having no row, we
        // cannot know which family it was — the prior rotation already removed it.)
        return false;
    }

    /**
     * [OAuth Phase 2] Throttled (~60s) last-used / last-ip touch for an access
     * token. Mutates ONLY this token's row, mirroring touch_cgpt_token().
     */
    private function touch_oauth_token($token_id, $ip) {
        $record = $this->get_oauth_token($token_id);
        if ($record === false) {
            return;
        }
        $last = intval($record['last_used']);
        if (time() - $last > self::LAST_USED_THROTTLE_SECONDS) {
            $record['last_used'] = time();
            $record['last_ip']   = (string) $ip;
            update_option($this->oauth_token_option_name($token_id), $record, 'no');
            // Re-assert index presence; expiry is unchanged by a touch.
            $this->oauth_token_index_add($token_id, $record['expires']);
        }
    }

    /**
     * [OAuth Phase 2] Revoke a single OAuth token row (access or refresh) by
     * token_id. Removes the per-token row and drops it from the index. Returns
     * true if a row was removed. Provided for later admin use.
     */
    private function revoke_oauth_token($token_id) {
        return $this->delete_oauth_token($token_id);
    }

    /** [OAuth Phase 2] Internal delete by token_id. */
    private function delete_oauth_token($token_id) {
        $removed = delete_option($this->oauth_token_option_name($token_id));
        $this->oauth_token_index_remove($token_id);
        return (bool) $removed;
    }

    /**
     * [OAuth Phase 2] Enumerate all OAuth tokens as token_id => normalized_record,
     * self-healing dead index entries. Provided for later admin use.
     */
    private function list_oauth_tokens() {
        $out = [];
        $index  = $this->oauth_normalize_index(get_option(self::OAUTH_TOKEN_INDEX_OPTION, []));
        $healed = [];
        foreach ($index as $token_id => $expiry) {
            $rec = $this->get_oauth_token($token_id);
            if ($rec !== false) {
                $out[$token_id] = $rec;
                // Preserve the known expiry; backfill a legacy (0) entry from the
                // row so the rewrite below migrates it into the new shape.
                $healed[$token_id] = ($expiry > 0) ? $expiry : intval($rec['expires']);
            }
        }
        // Rewrite only when the live/migrated map differs (dead rows dropped or a
        // legacy entry backfilled) — array == compares key=>value, order-agnostic.
        if ($healed != $index) {
            update_option(self::OAUTH_TOKEN_INDEX_OPTION, $healed, 'no');
        }
        return $out;
    }

    /**
     * [OAuth Phase 2] Upsert a token_id => expiry entry into the index (bounded
     * optimistic retry). The absolute expiry (unix) is carried IN the index so
     * oauth_prune_expired_tokens() can judge liveness without reading the
     * per-token row (the T082 fix). Idempotent: re-add with same expiry is a no-op.
     */
    private function oauth_token_index_add($token_id, $expiry) {
        $expiry = intval($expiry);
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = $this->oauth_normalize_index(get_option(self::OAUTH_TOKEN_INDEX_OPTION, []));
            if (isset($index[$token_id]) && $index[$token_id] === $expiry) {
                return true;
            }
            $index[$token_id] = $expiry;
            if (update_option(self::OAUTH_TOKEN_INDEX_OPTION, $index, 'no')) {
                return true;
            }
        }
        return false;
    }

    /** [OAuth Phase 2] Remove a token_id from the index (bounded optimistic retry). */
    private function oauth_token_index_remove($token_id) {
        for ($i = 0; $i < self::KEY_INDEX_MAX_RETRY; $i++) {
            $index = $this->oauth_normalize_index(get_option(self::OAUTH_TOKEN_INDEX_OPTION, []));
            if (!isset($index[$token_id])) {
                return true;
            }
            unset($index[$token_id]);
            if (update_option(self::OAUTH_TOKEN_INDEX_OPTION, $index, 'no')) {
                return true;
            }
        }
        return false;
    }

    /**
     * [OAuth Phase 2] Best-effort prune of expired OAuth-token rows. Mirrors
     * oauth_prune_expired_codes(): T082 stores the expiry IN the index (id =>
     * expiry), so the common case reads ONLY the single index option — no per-row
     * get_option(). A LEGACY entry (expiry 0) is read once to backfill its expiry
     * and migrate it to the new shape; after the first cycle the scan is O(1).
     */
    private function oauth_prune_expired_tokens() {
        $raw = get_option(self::OAUTH_TOKEN_INDEX_OPTION, []);
        if (!is_array($raw) || empty($raw)) {
            return;
        }
        $index   = $this->oauth_normalize_index($raw);
        $now     = time();
        $next    = [];
        $changed = false;
        foreach ($index as $token_id => $expiry) {
            if ($expiry <= 0) {
                // Legacy entry: read the row ONCE to backfill, then migrate.
                $changed = true;
                $row = get_option($this->oauth_token_option_name($token_id), null);
                if (is_array($row)) {
                    $rec    = $this->normalize_oauth_token_record($row);
                    $expiry = intval($rec['expires']);
                } else {
                    $expiry = 0; // row already gone — fall through to drop
                }
            }
            if ($expiry <= 0 || $now >= $expiry) {
                delete_option($this->oauth_token_option_name($token_id));
                $changed = true;
                continue;
            }
            $next[$token_id] = $expiry;
        }
        if ($changed) {
            update_option(self::OAUTH_TOKEN_INDEX_OPTION, $next, 'no');
        }
    }

    /**
     * Sentinel-guarded, idempotent migration from the legacy monolithic
     * `connectmwp_keys` array to atomic per-key rows. NON-DESTRUCTIVE: the
     * legacy row is intentionally retained this release as a backward-read
     * fallback (dropped in v2.0.28). Preserves all six fields verbatim.
     */
    public function maybe_migrate_legacy_keys() {
        // Atomic guard: add_option fails if the sentinel already exists, so only
        // the first worker to reach this performs the migration.
        if (!add_option(self::KEY_MIGRATED_FLAG, '0', '', 'no')) {
            return; // already migrated (or in progress) — short-circuit
        }

        $legacy = get_option(self::LEGACY_KEYS_OPTION, []);
        if (!is_array($legacy) || empty($legacy)) {
            // Fresh install or nothing to migrate. Mark done.
            update_option(self::KEY_MIGRATED_FLAG, self::version(), 'no');
            return;
        }

        foreach ($legacy as $key_id => $raw) {
            $record = $this->normalize_key_record($raw);
            // add_key is atomic create; if a per-key row already exists from a
            // prior lazy migration, add_option returns false and we skip — the
            // existing row (already migrated) is authoritative.
            $this->add_key($key_id, $record);
        }

        // Seed/refresh the index from the now-written per-key rows.
        $this->rebuild_key_index();

        // Record completion (and the version that did it). Legacy row stays put.
        update_option(self::KEY_MIGRATED_FLAG, self::version(), 'no');
    }

    // ---- Thin wrappers preserving existing call signatures -----------------

    /**
     * Hot-path key lookup used by verify_request_signature. Now a single
     * per-key option read (independent of total key count) via the DAL.
     */
    private function find_key_by_id($key_id) {
        return $this->get_key($key_id);
    }

    /**
     * Throttled (~60s) last-used / last-ip touch. Mutates ONLY this key's row
     * (atomic) — the array clobber that could drop a concurrent enroll is gone.
     */
    private function update_key_last_used($user_id, $key_id) {
        $record = $this->get_key($key_id);
        if ($record === false) {
            return;
        }
        $last_used_str = $record['last_used'] ?? '';
        $last_used_time = !empty($last_used_str) && $last_used_str !== 'Never' ? strtotime($last_used_str) : 0;
        if (time() - $last_used_time > self::LAST_USED_THROTTLE_SECONDS) {
            $this->update_key_fields($key_id, [
                'last_used' => current_time('mysql'),
                'last_ip'   => $this->get_client_ip(),
            ]);
        }
    }

    /**
     * Client IP. Default and only trusted source: REMOTE_ADDR (un-forgeable when
     * talking to PHP directly). Forwarding headers (X-Forwarded-For / X-Real-IP)
     * are honoured ONLY when this site is explicitly declared to sit behind a
     * trusted reverse proxy via is_behind_trusted_proxy() — default OFF, so
     * upgrade behavior is unchanged and forged headers can never be trusted.
     */
    private function get_client_ip() {
        $remote = (!empty($_SERVER['REMOTE_ADDR']) && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP))
            ? $_SERVER['REMOTE_ADDR'] : '';

        if ($this->is_behind_trusted_proxy()) {
            // Single trusted proxy: take the LAST hop it appended (the one it
            // can vouch for), not the spoofable leftmost client-supplied value.
            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
                $cand  = end($parts);
                if (filter_var($cand, FILTER_VALIDATE_IP)) {
                    return $cand;
                }
            }
            if (!empty($_SERVER['HTTP_X_REAL_IP']) && filter_var(trim($_SERVER['HTTP_X_REAL_IP']), FILTER_VALIDATE_IP)) {
                return trim($_SERVER['HTTP_X_REAL_IP']);
            }
        }

        // Default path. The no-REMOTE_ADDR fallback collapses onto a single
        // deterministic 'unknown' bucket — acceptable: REMOTE_ADDR is present on
        // all real HTTP requests, the bucket auto-expires, and never fails open
        // to a forgeable forwarded value.
        return $remote !== '' ? $remote : 'unknown';
    }

    /**
     * SSOT: is this site behind a trusted reverse proxy? Constant override
     * (infra-as-code) wins; else the admin option; default false. Every
     * "may I trust forwarding headers?" decision routes through here (T041).
     */
    private function is_behind_trusted_proxy() {
        if (defined('CONNECTMWP_TRUST_PROXY')) {
            return (bool) CONNECTMWP_TRUST_PROXY;
        }
        return (bool) get_option('connectmwp_trust_proxy', false);
    }

    // ------------------------------------------------------------------------
    // Authorization (capability) helpers — SSOT for "may $this->bound_user_id do
    // X?". These perform NO authentication: they assume the caller has already
    // verified a signature (verify_request_signature) or a bearer token
    // (verify_token_request) and populated $this->bound_user_id. The two concerns
    // are deliberately split so dispatch_action can authorize the token path
    // (which has no signature) against the already-set bound user. The public
    // check_* permission_callbacks below layer signature verification on top of
    // these for the REST transport.
    private function cap_can_read(): bool {
        return user_can($this->bound_user_id, 'edit_posts');
    }

    private function cap_can_edit(): bool {
        return user_can($this->bound_user_id, 'edit_posts');
    }

    private function cap_can_edit_post($request): bool {
        return user_can($this->bound_user_id, 'edit_post', intval($request['id']));
    }

    private function cap_can_delete_post($request): bool {
        return user_can($this->bound_user_id, 'delete_post', intval($request['id']));
    }

    private function cap_can_upload(): bool {
        return user_can($this->bound_user_id, 'upload_files');
    }

    private function cap_can_taxonomy(): bool {
        return user_can($this->bound_user_id, 'manage_categories');
    }

    // Permission callbacks (REST transport): authenticate via signature, THEN
    // authorize via the cap_* helpers. Observable behavior is identical to the
    // pre-split callbacks — verify signature first, fail closed, then user_can.
    public function check_read_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return $this->cap_can_read();
    }

    public function check_edit_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return $this->cap_can_edit();
    }

    public function check_edit_post_permission($request) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return $this->cap_can_edit_post($request);
    }

    public function check_delete_post_permission($request) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return $this->cap_can_delete_post($request);
    }

    public function check_upload_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return $this->cap_can_upload();
    }

    public function check_taxonomy_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return $this->cap_can_taxonomy();
    }

    // Signature-only gate — used by /whoami. Any valid signature passes; the
    // returned payload only echoes what this caller can already discover by
    // signing requests + observing 403s, so it's safe at this scope.
    public function check_signature_only($request = null) {
        return $this->verify_request_signature($request);
    }

    /**
     * Build the identity payload returned by /enroll and /whoami so the two
     * stay in sync. Includes site + bound-user + capability map. Capability
     * keys mirror what each tool's permission_callback actually checks.
     */
    private function build_identity_payload($key_id, $bound_user_id, $label = null) {
        $user = get_userdata(intval($bound_user_id));
        $user_payload = [
            'login'        => $user ? $user->user_login : null,
            'display_name' => $user ? ($user->display_name ?: $user->user_login) : null,
            'roles'        => $user && is_array($user->roles) ? array_values($user->roles) : [],
        ];

        // Mirror the capability checks each tool's permission_callback runs.
        $caps = [
            'edit_posts'        => $user ? user_can($bound_user_id, 'edit_posts') : false,
            'publish_posts'     => $user ? user_can($bound_user_id, 'publish_posts') : false,
            'edit_others_posts' => $user ? user_can($bound_user_id, 'edit_others_posts') : false,
            'upload_files'      => $user ? user_can($bound_user_id, 'upload_files') : false,
            'manage_categories' => $user ? user_can($bound_user_id, 'manage_categories') : false,
            'delete_posts'      => $user ? user_can($bound_user_id, 'delete_posts') : false,
        ];

        $payload = [
            'success' => true,
            'key_id'  => $key_id,
            'site'    => [
                'title'          => html_entity_decode(get_bloginfo('name'), ENT_QUOTES, 'UTF-8'),
                'url'            => home_url(),
                'plugin_version' => self::version(),
            ],
            'user'         => $user_payload,
            'capabilities' => $caps,
        ];

        if ($label !== null) {
            $payload['label'] = $label;
        }

        return $payload;
    }

    /**
     * /whoami handler — returns the identity payload for the currently-authenticated
     * signer. Looks up the current key in stored options to also surface its label.
     */
    public function whoami_handler(?WP_REST_Request $request = null) {
        // matched_key_id is set only by the Ed25519 signature path. On the
        // ChatGPT/token transport (connectmwp_status) there is no key, so
        // key_id is '' here by design — the bound-user + capability payload
        // below is still fully populated from $this->bound_user_id.
        $key_id = $this->matched_key_id;
        $label = null;
        if (!empty($key_id)) {
            $rec = $this->get_key($key_id);
            if ($rec !== false && !empty($rec['label'])) {
                $label = $rec['label'];
            }
        }
        return new WP_REST_Response(
            $this->build_identity_payload($key_id, $this->bound_user_id, $label),
            200
        );
    }

    /**
     * Admin-AJAX endpoint: report the current pairing state so the settings
     * page can poll for completion and self-update without a manual refresh.
     * Admin-only (relies on WP's cookie auth + a fresh nonce). Returns:
     *   {
     *     code_active:    bool,    // is a non-expired pairing code currently issued?
     *     expires_in:     int,     // seconds until that code expires (0 if none)
     *     total_keys:     int,     // total currently-paired clients
     *     latest_key_id:  str|null,
     *     latest_created: str|null,// MySQL datetime
     *     latest_label:   str|null
     *   }
     * The JS on the page compares total_keys / latest_key_id against the values
     * captured at page-load time and triggers a success-flash + reload when they change.
     */
    public function pairing_status_handler() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'forbidden'], 403);
        }
        check_ajax_referer('connectmwp_pairing_status');

        $stored = get_option('connectmwp_enrollment_code');
        $code_active = false;
        $expires_in = 0;
        if (is_array($stored) && !empty($stored['code']) && intval($stored['expires']) > time()) {
            $code_active = true;
            $expires_in = max(0, intval($stored['expires']) - time());
        }

        // (T058) Cheap path: total from the index length (O(1)) + newest client
        // from the denormalized hint, avoiding the per-key option fan-out on this
        // 3s poll. Fall back to the authoritative list_keys() only when the hint
        // is absent (pre-upgrade sites, or just after the latest key was revoked).
        $index = get_option(self::KEY_INDEX_OPTION, []);
        $total_keys = is_array($index) ? count($index) : 0;

        $latest_key_id  = null;
        $latest_created = null;
        $latest_label   = null;

        $hint = get_option(self::LATEST_CLIENT_OPTION);
        if (is_array($hint) && !empty($hint['key_id'])) {
            $latest_key_id  = $hint['key_id'];
            $latest_created = $hint['created'] ?? null;
            $latest_label   = $hint['label']   ?? null;
        } else {
            // Fallback: authoritative resolve (also re-syncs total to the rows).
            $keys = $this->list_keys();
            $total_keys = count($keys);
            if ($total_keys > 0) {
                $sorted = $keys;
                uasort($sorted, function($a, $b) {
                    return strcmp($b['created'] ?? '', $a['created'] ?? '');
                });
                $first_id = array_key_first($sorted);
                $latest_key_id  = $first_id;
                $latest_created = $sorted[$first_id]['created'] ?? null;
                $latest_label   = $sorted[$first_id]['label']   ?? null;
            }
        }

        wp_send_json([
            'code_active'    => $code_active,
            'expires_in'     => $expires_in,
            'total_keys'     => $total_keys,
            'latest_key_id'  => $latest_key_id,
            'latest_created' => $latest_created,
            'latest_label'   => $latest_label,
        ]);
    }

    /**
     * Build the two MCP connector URLs an admin pastes into ChatGPT's connector
     * settings, derived from this site's REST base (single source of truth via
     * rest_url()) — NOT hand-concatenated. Returns:
     *   - 'header': the canonical endpoint; the token travels as
     *     `Authorization: Bearer <token>` / API key.
     *   - 'path'  : the fallback that embeds the token in the path, for hosts
     *     that strip the Authorization header at the edge proxy.
     * The plaintext token is interpolated into the path form ONLY when a
     * freshly-minted plaintext is supplied (i.e. immediately after generate);
     * the listing UI never calls this with a plaintext.
     */
    /**
     * SSOT for whether the URL-embedded (path) token fallback is enabled. OFF by
     * default. Gates BOTH the auth source (#3, the route param in
     * verify_token_request) and the surfacing of the path-token connector URL in
     * the admin UI. The two HEADER auth sources are never gated by this.
     */
    private function cgpt_path_token_enabled(): bool {
        return (bool) get_option(self::CGPT_ALLOW_PATH_TOKEN_OPTION, false);
    }

    private function cgpt_connector_urls($plaintext = null) {
        $base = rest_url(self::API_NAMESPACE . '/mcp');
        $base = rtrim($base, '/');
        $path = $base;
        if (is_string($plaintext) && $plaintext !== '') {
            $path = $base . '/' . rawurlencode($plaintext);
        }
        return [
            'header' => $base,
            'path'   => $path,
        ];
    }

    /**
     * Format a `current_time('mysql')` string (no timezone marker) into the
     * repo-standard `YYYY-MM-DD HH:MM` display string, interpreted in the
     * WP-configured timezone. Mirrors the per-key enrichment in
     * render_settings_page(). Returns '' for blank/unparseable input so the
     * caller can substitute its own placeholder.
     */
    private function format_cgpt_timestamp($mysql) {
        if (!is_string($mysql) || $mysql === '') {
            return '';
        }
        if (function_exists('wp_timezone')) {
            $dt = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $mysql, wp_timezone());
            if ($dt instanceof DateTimeImmutable) {
                return $dt->format('Y-m-d H:i');
            }
        }
        return $mysql;
    }

    /**
     * Admin-AJAX: mint a new ChatGPT bearer token (T5). Gated by nonce +
     * manage_options exactly like pairing_status_handler. The plaintext token is
     * returned to the requesting admin's OWN authenticated browser session and
     * is never logged or stored — the only place the plaintext ever exists.
     */
    public function cgpt_generate_handler() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'forbidden', 'message' => 'You do not have permission to do this.'], 403);
        }
        check_ajax_referer('connectmwp_cgpt');

        // Enforce the per-site cap BEFORE doing any work. Revocation is the only
        // way past it — never silently evict an existing token.
        $existing = $this->list_cgpt_tokens();
        if (count($existing) >= self::MAX_CGPT_TOKENS_PER_SITE) {
            wp_send_json_error([
                'message' => sprintf(
                    'You have reached the limit of %d ChatGPT tokens for this site. Revoke an existing token below before generating a new one.',
                    self::MAX_CGPT_TOKENS_PER_SITE
                ),
            ], 409);
        }

        $bound_user_id = isset($_POST['bound_user_id']) ? intval($_POST['bound_user_id']) : 0;
        $label         = isset($_POST['label']) ? sanitize_text_field(wp_unslash($_POST['label'])) : '';
        if ($label === '') {
            $label = 'ChatGPT';
        }

        // Validate the delegation target: the user must exist AND be able to
        // edit posts (the minimum capability any token-driven write needs).
        // Binding to a non-author would mint a token that can never publish.
        if ($bound_user_id <= 0) {
            wp_send_json_error(['message' => 'Please choose a WordPress user to connect ChatGPT as.'], 400);
        }
        $target = get_userdata($bound_user_id);
        if (!$target) {
            wp_send_json_error(['message' => 'That WordPress user no longer exists.'], 400);
        }
        if (!user_can($bound_user_id, 'edit_posts')) {
            wp_send_json_error(['message' => 'That user cannot edit posts, so a ChatGPT token bound to them could not publish. Choose a user with at least author-level access.'], 400);
        }

        $result = $this->mint_cgpt_token($bound_user_id, $label);
        // mint_cgpt_token() returns false on a storage failure (id collision or a
        // transient DB error) — the row was NOT written, so surface a retryable
        // error rather than handing back an unusable plaintext.
        if ($result === false) {
            wp_send_json_error(['message' => 'Could not generate token, please try again.'], 500);
        }

        $urls = $this->cgpt_connector_urls($result['plaintext']);

        // The default response presents the header-form connector URL + the bare
        // token as SEPARATE fields (admin pastes the bare token into ChatGPT's
        // API-key field; nothing forces copying a URL that contains the secret).
        // The path-token URL — which embeds the secret in the URL and would land
        // in access logs — is ONLY included when the fallback is explicitly
        // enabled (sec review MEDIUM, reviewer point d).
        $response = [
            'token'         => $result['plaintext'],
            'token_id'      => $result['token_id'],
            'label'         => $label,
            'bound_user_id' => $bound_user_id,
            'user_display'  => $target->display_name ?: $target->user_login,
            'user_login'    => $target->user_login,
            'created'       => $this->format_cgpt_timestamp($result['record']['created'] ?? ''),
            'connector_url' => $urls['header'],
        ];
        if ($this->cgpt_path_token_enabled()) {
            $response['connector_url_path'] = $urls['path'];
        }

        // NOTE: the plaintext is returned exactly once, here, to the admin's own
        // browser. It is intentionally NOT logged anywhere.
        wp_send_json_success($response);
    }

    /**
     * Admin-AJAX: revoke (delete) a single ChatGPT token by id (T5). Gated by
     * nonce + manage_options. delete_cgpt_token() is idempotent; we report
     * whether a live row was actually removed.
     */
    public function cgpt_revoke_handler() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'forbidden', 'message' => 'You do not have permission to do this.'], 403);
        }
        check_ajax_referer('connectmwp_cgpt');

        $token_id = isset($_POST['token_id']) ? sanitize_text_field(wp_unslash($_POST['token_id'])) : '';
        if ($token_id === '') {
            wp_send_json_error(['message' => 'Missing token id.'], 400);
        }

        $removed = $this->delete_cgpt_token($token_id);
        if (!$removed) {
            wp_send_json_error(['message' => 'That token was already revoked or no longer exists.'], 404);
        }

        wp_send_json_success(['token_id' => $token_id]);
    }

    /**
     * Format an absolute unix timestamp (as stored on OAuth token records via
     * time()) into the repo-standard `YYYY-MM-DD HH:MM` display string in the
     * WP-configured timezone. Mirrors format_cgpt_timestamp() but for the
     * integer-unix schema the OAuth DAL uses. Returns '' for non-positive input
     * so the caller can substitute its own placeholder.
     */
    private function format_oauth_timestamp($unix) {
        $unix = intval($unix);
        if ($unix <= 0) {
            return '';
        }
        if (function_exists('wp_timezone')) {
            $dt = (new DateTimeImmutable('@' . $unix))->setTimezone(wp_timezone());
            return $dt->format('Y-m-d H:i');
        }
        return gmdate('Y-m-d H:i', $unix);
    }

    /**
     * Revoke an ENTIRE OAuth connection: delete every token row (access +
     * refresh + any rotations) that shares the given `family` id. Iterates the
     * live token list and revoke_oauth_token()s each match. Returns the number
     * of rows removed. Empty / blank family matches nothing and returns 0.
     */
    private function revoke_oauth_family($family) {
        $family = (string) $family;
        if ($family === '') {
            return 0;
        }
        $removed = 0;
        foreach ($this->list_oauth_tokens() as $token_id => $record) {
            if ((string) $record['family'] === $family) {
                if ($this->revoke_oauth_token($token_id)) {
                    $removed++;
                }
            }
        }
        return $removed;
    }

    /**
     * Admin-AJAX: revoke a whole connected OAuth app by token-family id. Gated by
     * nonce + manage_options exactly like cgpt_revoke_handler. Deletes BOTH the
     * access and refresh tokens (and any rotations) so the app is fully
     * disconnected. Admin UX only — NEVER on the MCP traffic path. No token
     * plaintext is ever read or returned (only sha256 hashes are stored anyway).
     */
    public function oauth_revoke_handler() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'forbidden', 'message' => 'You do not have permission to do this.'], 403);
        }
        check_ajax_referer('connectmwp_oauth_manage');

        $family = isset($_POST['family']) ? sanitize_text_field(wp_unslash($_POST['family'])) : '';
        if ($family === '') {
            wp_send_json_error(['message' => 'Missing connection id.'], 400);
        }

        $removed = $this->revoke_oauth_family($family);
        if ($removed === 0) {
            wp_send_json_error(['message' => 'That connection was already revoked or no longer exists.'], 404);
        }

        wp_send_json_success(['family' => $family, 'removed' => $removed]);
    }

    /**
     * Admin-AJAX: toggle the URL-embedded (path) token fallback on/off. Gated by
     * nonce + manage_options, exactly like the generate/revoke handlers. This is
     * the ONLY way to flip connectmwp_cgpt_allow_path_token, which is OFF by
     * default (sec review MEDIUM: a path token lands in access logs). Enabling it
     * starts honoring the /mcp/<token> route param as an auth source and reveals
     * the path-token connector URL in the admin UI. The token value is never read
     * or logged here.
     */
    public function cgpt_set_path_token_handler() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'forbidden', 'message' => 'You do not have permission to do this.'], 403);
        }
        check_ajax_referer('connectmwp_cgpt');

        // Coerce the posted flag to a strict boolean. Accept "1"/"true"/"on".
        $raw     = isset($_POST['enabled']) ? sanitize_text_field(wp_unslash($_POST['enabled'])) : '';
        $enabled = in_array(strtolower($raw), ['1', 'true', 'on', 'yes'], true);

        update_option(self::CGPT_ALLOW_PATH_TOKEN_OPTION, $enabled ? true : false, false);

        wp_send_json_success(['enabled' => $enabled]);
    }

    /**
     * Handle Public Key Enrollment
     */
    public function enroll_client_handler(WP_REST_Request $request) {
        // Enforce SSL unless this is a genuine loopback request (local dev over
        // plain HTTP). T093: the localhost check is gated SOLELY on a loopback
        // REMOTE_ADDR (un-forgeable when talking directly to PHP) — NOT on the
        // HTTP_HOST header, which is client-controllable and must never gate a
        // security decision (a remote attacker could send `Host: localhost` to
        // enroll over plaintext). Production enrollment is always HTTPS; this
        // bypass only ever applies to a real 127.0.0.1/::1 caller.
        $client_ip = $this->get_client_ip();
        $is_localhost = in_array($client_ip, ['127.0.0.1', '::1'], true);
        if (!is_ssl() && !$is_localhost) {
            return new WP_REST_Response(['success' => false, 'error' => 'HTTPS is required for enrollment.'], 403);
        }

        // Extract the enrollment code from any of its three transports BEFORE
        // touching the rate-limit transient. All three reads are cheap and do no
        // DB write, so moving them ahead of the limiter is safe (T041).
        $custom_code = '';
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'X-ConnectMWP-Enroll-Code') === 0) {
                    $custom_code = $value;
                    break;
                }
            }
        }
        if (empty($custom_code) && isset($_SERVER['HTTP_X_CONNECTMWP_ENROLL_CODE'])) {
            $custom_code = $_SERVER['HTTP_X_CONNECTMWP_ENROLL_CODE'];
        }
        if (empty($custom_code)) {
            $params = $request->get_json_params();
            if (empty($params)) {
                $params = $request->get_body_params();
            }
            $custom_code = !empty($params['code']) ? sanitize_text_field($params['code']) : '';
        }

        // (T041) Reject structurally-invalid / missing codes BEFORE any
        // rate-limit DB write, so a flood of malformed/garbage codes creates
        // zero wp_options rows. A well-formed-but-wrong code still meters below.
        // Collapsing "missing" and "malformed" into one 401 also avoids telling
        // an attacker whether their guess had the right shape vs was absent.
        if (!$this->is_well_formed_enroll_code($custom_code)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Enrollment code is required'], 401);
        }

        // Transient-based IP rate limiting (reached only for well-formed codes).
        // Reuse the $client_ip already computed above for the SSL/localhost gate.
        $ip_key = 'cmwp_enroll_limit_' . md5($client_ip);
        $attempts = intval(get_transient($ip_key));
        if ($attempts >= 5) {
            return new WP_REST_Response(['success' => false, 'error' => 'Too many enrollment attempts. Please try again later.'], 429);
        }

        // Validate single-use enrollment code
        $stored = get_option('connectmwp_enrollment_code');
        if (!is_array($stored) || empty($stored['code']) || !hash_equals($stored['code'], $custom_code)) {
            set_transient($ip_key, $attempts + 1, 600); // count well-formed misses only; lock for 10 mins
            return new WP_REST_Response(['success' => false, 'error' => 'Invalid enrollment code'], 401);
        }

        if (time() > intval($stored['expires'])) {
            delete_option('connectmwp_enrollment_code');
            return new WP_REST_Response(['success' => false, 'error' => 'Enrollment code has expired'], 401);
        }

        $params = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_body_params();
        }

        $public_key = !empty($params['public_key']) ? sanitize_text_field($params['public_key']) : '';
        $label = !empty($params['label']) ? sanitize_text_field($params['label']) : 'Local client';

        if (empty($public_key)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Public key is required'], 400);
        }

        // Validate public key length (must be base64-encoded 32-byte Ed25519 raw public key)
        $raw_pub = base64_decode($public_key);
        if (strlen($raw_pub) !== 32) {
            return new WP_REST_Response(['success' => false, 'error' => 'Invalid public key format'], 400);
        }

        // (T064) Atomic single-use claim — the serialization point, placed AFTER
        // input validation. The window between the hash_equals above and the
        // delete_option on success is otherwise wide enough that two concurrent
        // requests presenting the SAME valid code both pass and both mint a key;
        // and because both succeed, a stolen code leaves no visible "Invalid code"
        // tamper signal for the victim. add_option is atomic (same primitive as
        // the replay defense): exactly one racer wins the claim; the rest get the
        // standard invalid-code 401. Acquired AFTER the public-key checks so a
        // malformed-but-valid-code request can't burn the claim and brick the
        // user's legitimate retry, and AFTER hash_equals so a code-guessing flood
        // never creates claim rows (preserves the T041 no-bloat property).
        $claim_key = 'cmwp_enroll_claimed_' . hash('sha256', $custom_code);
        if (!add_option($claim_key, time(), '', 'no')) {
            return new WP_REST_Response(['success' => false, 'error' => 'Invalid enrollment code'], 401);
        }

        $key_id = 'cmwp_key_' . bin2hex(random_bytes(8));
        $created_now = current_time('mysql');

        // Atomic per-key create (T039). add_key writes ONLY this key's row, so a
        // concurrent enroll of a different key cannot clobber it and vice versa.
        $this->add_key($key_id, [
            'public_key'     => $public_key,
            'bound_user_id'  => intval($stored['user_id']),
            'label'          => $label,
            'created'        => $created_now,
            'last_used'      => '',
            'last_ip'        => ''
        ]);

        // Refresh the pairing-poll "latest client" hint (T058) so the settings
        // page's 3s poll detects this new pairing from one option read.
        update_option(self::LATEST_CLIENT_OPTION, [
            'key_id'  => $key_id,
            'created' => $created_now,
            'label'   => $label,
        ], 'no');

        // Delete pairing code and rate-limit transient immediately on success.
        // Also drop the single-use claim sentinel (T064) — the code is gone, so
        // the sentinel has served its purpose; cleaning it up bounds wp_options.
        delete_option('connectmwp_enrollment_code');
        delete_option($claim_key);
        delete_transient($ip_key);

        return new WP_REST_Response(
            $this->build_identity_payload($key_id, intval($stored['user_id']), $label),
            200
        );
    }

    /**
     * Canonical wire-format check for an enrollment code: exactly
     * ENROLL_CODE_HEX_LEN lowercase hex chars (the output of
     * bin2hex(random_bytes(16)) in generate_enrollment_code()). Cheap, pure,
     * no DB. SSOT for "is this a syntactically valid enroll code?" (T041).
     */
    private function is_well_formed_enroll_code($code) {
        if (!is_string($code) || $code === '') {
            return false;
        }
        if (strlen($code) !== self::ENROLL_CODE_HEX_LEN) {
            return false;
        }
        return (bool) preg_match('/^[0-9a-f]{' . self::ENROLL_CODE_HEX_LEN . '}$/', $code);
    }

    private function generate_enrollment_code() {
        $code = bin2hex(random_bytes(16));
        $expiry = time() + 600; // 10 minutes
        $data = [
            'code' => $code,
            'user_id' => get_current_user_id(),
            'expires' => $expiry
        ];
        update_option('connectmwp_enrollment_code', $data, 'no');
        return $code;
    }

    /**
     * Object-level read authorization for a single post, session-less.
     * Uses the WP `read_post` meta-cap, which map_meta_cap resolves correctly
     * for public / private / pending / trashed / future statuses against the
     * bound user. Decides against $this->bound_user_id only — there is no
     * current WP user to consult, by design.
     * SSOT for "may this paired key read THIS post object?" (T038).
     */
    private function can_read_post($post) {
        if (!$post || empty($this->bound_user_id)) {
            return false; // fail closed
        }
        return user_can($this->bound_user_id, 'read_post', $post->ID);
    }

    /**
     * REST Handlers
     */
    public function get_posts_handler(WP_REST_Request $request) {
        $limit = $request->get_param('limit') ? intval($request->get_param('limit')) : self::DEFAULT_PER_PAGE;
        $limit = min(self::MAX_PER_PAGE_POSTS, max(self::MIN_PER_PAGE, $limit));
        $offset = $request->get_param('offset') ? intval($request->get_param('offset')) : 0;
        $offset = max(0, $offset);
        
        $fields_param = $request->get_param('fields');
        if ($fields_param) {
            $requested_fields = array_map('trim', explode(',', strtolower($fields_param)));
        } else {
            $requested_fields = ['id', 'title', 'url', 'link', 'status', 'date'];
        }
        
        $query_args = [
            'post_type'      => 'post',
            'post_status'    => ['publish', 'draft'],
            'posts_per_page' => $limit,
            'offset'         => $offset,
        ];

        // Scope drafts to own user if user lacks edit_others_posts
        if (!user_can($this->bound_user_id, 'edit_others_posts')) {
            $query_args['author'] = $this->bound_user_id;
        }

        $posts_query = new WP_Query($query_args);
        $total = intval($posts_query->found_posts);
        $has_more = ($offset + count($posts_query->posts)) < $total;

        $posts = [];
        foreach ($posts_query->posts as $post) {
            $post_item = [];
            if (in_array('id', $requested_fields, true)) {
                $post_item['id'] = $post->ID;
            }
            if (in_array('title', $requested_fields, true)) {
                $post_item['title'] = $post->post_title;
            }
            if (in_array('url', $requested_fields, true) || in_array('link', $requested_fields, true)) {
                $post_item['url'] = get_permalink($post->ID);
                $post_item['link'] = get_permalink($post->ID);
            }
            if (in_array('status', $requested_fields, true)) {
                $post_item['status'] = $post->post_status;
            }
            if (in_array('date', $requested_fields, true)) {
                $post_item['date'] = $post->post_date;
            }
            if (in_array('content', $requested_fields, true)) {
                $post_item['content'] = $post->post_content;
            }
            $posts[] = $post_item;
        }

        return new WP_REST_Response([
            'success'  => true,
            'posts'    => $posts,
            'total'    => $total,
            'has_more' => $has_more
        ], 200);
    }

    public function get_post_handler(WP_REST_Request $request) {
        $post_id = intval($request['id']);
        $post = get_post($post_id);
        if (!$post || $post->post_type !== 'post') {
            return new WP_REST_Response(['success' => false, 'error' => 'Post not found.'], 404);
        }

        // Object-level read authorization for ALL statuses (T038).
        // The `read_post` meta-cap covers draft/private/pending/trash/future
        // correctly; the draft-only check it replaces left private/trash readable
        // by any edit_posts-capable (e.g. Contributor) key — a textbook IDOR.
        if (!$this->can_read_post($post)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403);
        }

        $fields_param = $request->get_param('fields');
        if ($fields_param) {
            $requested_fields = array_map('trim', explode(',', strtolower($fields_param)));
        } else {
            $requested_fields = ['id', 'title', 'url', 'link', 'status', 'date', 'content', 'featured_media', 'categories', 'tags'];
        }

        $post_item = [];
        if (in_array('id', $requested_fields, true)) {
            $post_item['id'] = $post->ID;
        }
        if (in_array('title', $requested_fields, true)) {
            $post_item['title'] = $post->post_title;
        }
        if (in_array('url', $requested_fields, true) || in_array('link', $requested_fields, true)) {
            $post_item['url'] = get_permalink($post->ID);
            $post_item['link'] = get_permalink($post->ID);
        }
        if (in_array('status', $requested_fields, true)) {
            $post_item['status'] = $post->post_status;
        }
        if (in_array('date', $requested_fields, true)) {
            $post_item['date'] = $post->post_date;
        }
        if (in_array('content', $requested_fields, true)) {
            $post_item['content'] = $post->post_content;
        }
        if (in_array('featured_media', $requested_fields, true)) {
            $post_item['featured_media'] = has_post_thumbnail($post->ID) ? intval(get_post_thumbnail_id($post->ID)) : 0;
        }
        if (in_array('categories', $requested_fields, true)) {
            $post_categories = wp_get_post_categories($post->ID, ['fields' => 'ids']);
            $post_item['categories'] = is_array($post_categories) ? array_map('intval', $post_categories) : [];
        }
        if (in_array('tags', $requested_fields, true)) {
            $post_tags = wp_get_post_tags($post->ID, ['fields' => 'ids']);
            $post_item['tags'] = is_array($post_tags) ? array_map('intval', $post_tags) : [];
        }

        return new WP_REST_Response(['success' => true, 'post' => $post_item], 200);
    }

    public function create_post_handler(WP_REST_Request $request) {
        $params = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_body_params();
        }

        $title = !empty($params['title']) ? sanitize_text_field($params['title']) : '';
        $content = !empty($params['content']) ? wp_kses_post($params['content']) : '';
        $status = !empty($params['status']) ? sanitize_key($params['status']) : 'draft';
        // Constrain to a known-safe status allowlist so a low-priv token can't set
        // unexpected statuses (future, inherit, private, etc.). Orthogonal to the
        // publish capability gate below — publish still requires publish_posts.
        if (!in_array($status, ['draft', 'publish', 'trash', 'pending'], true)) {
            $status = 'draft';
        }
        $categories = !empty($params['categories']) ? array_map('intval', (array) $params['categories']) : [];
        $tags = !empty($params['tags']) ? array_map('intval', (array) $params['tags']) : [];
        $featured_media = !empty($params['featured_media']) ? intval($params['featured_media']) : 0;

        if (empty($title)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Title is required'], 400);
        }

        // Contributor publish privilege check
        if ($status === 'publish' && !user_can($this->bound_user_id, 'publish_posts')) {
            $status = 'pending';
        }

        $post_id = wp_insert_post([
            'post_title'     => $title,
            'post_content'   => $content,
            'post_status'    => $status,
            'post_category'  => $categories,
            'tags_input'     => $tags,
            'post_author'    => $this->bound_user_id,
        ]);

        if (is_wp_error($post_id)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Failed to create post.'], 500);
        }

        if ($featured_media > 0) {
            $attachment = get_post($featured_media);
            if ($attachment && $attachment->post_type === 'attachment') {
                set_post_thumbnail($post_id, $featured_media);
            }
        }

        return new WP_REST_Response([
            'success'   => true,
            'post_id'   => $post_id,
            'url'       => get_permalink($post_id),
            'edit_link' => get_edit_post_link($post_id, 'raw')
        ], 200);
    }

    public function update_post_handler(WP_REST_Request $request) {
        $post_id = intval($request['id']);

        // (T065) Scope the mutation to actual posts. The edit_post meta-cap in the
        // permission_callback passes for any object the bound user can edit —
        // including Pages and other CPTs — so without this guard the "posts" tool
        // could mutate non-post objects, widening blast radius beyond its contract.
        // Mirrors the existing post_type gate in get_post_handler.
        $existing_post = get_post($post_id);
        if (!$existing_post || $existing_post->post_type !== 'post') {
            return new WP_REST_Response(['success' => false, 'error' => 'Post not found.'], 404);
        }

        $params = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_body_params();
        }

        $post_data = ['ID' => $post_id];
        
        if (isset($params['title'])) {
            $post_data['post_title'] = sanitize_text_field($params['title']);
        }
        if (isset($params['content'])) {
            $post_data['post_content'] = wp_kses_post($params['content']);
        }
        if (isset($params['status'])) {
            $status = sanitize_key($params['status']);
            // Constrain to a known-safe status allowlist so a low-priv token can't
            // set unexpected statuses (future, inherit, private, etc.). Orthogonal
            // to the publish capability gate below — publish still requires
            // publish_posts.
            if (!in_array($status, ['draft', 'publish', 'trash', 'pending'], true)) {
                $status = 'draft';
            }
            if ($status === 'publish' && !user_can($this->bound_user_id, 'publish_posts')) {
                $current_post = get_post($post_id);
                if ($current_post && $current_post->post_status !== 'publish') {
                    $post_data['post_status'] = 'pending';
                }
            } else {
                $post_data['post_status'] = $status;
            }
        }
        if (isset($params['categories'])) {
            $post_data['post_category'] = array_map('intval', (array) $params['categories']);
        }
        if (isset($params['tags'])) {
            $post_data['tags_input'] = array_map('intval', (array) $params['tags']);
        }

        $updated_id = wp_update_post($post_data);
        if (is_wp_error($updated_id)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Failed to update post.'], 500);
        }

        if (!empty($params['featured_media'])) {
            $featured_media = intval($params['featured_media']);
            $attachment = get_post($featured_media);
            if ($attachment && $attachment->post_type === 'attachment') {
                set_post_thumbnail($post_id, $featured_media);
            }
        }

        return new WP_REST_Response(['success' => true, 'post_id' => $post_id, 'url' => get_permalink($post_id)], 200);
    }

    public function delete_post_handler(WP_REST_Request $request) {
        $post_id = intval($request['id']);
        $params = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_body_params();
        }
        $force = isset($params['force']) ? filter_var($params['force'], FILTER_VALIDATE_BOOLEAN) : false;

        $post = get_post($post_id);
        // (T065) Same post_type scoping as update — the delete_post meta-cap would
        // otherwise allow trashing Pages / CPTs through the "posts" tool.
        if (!$post || $post->post_type !== 'post') {
            return new WP_REST_Response(['success' => false, 'error' => 'Post not found.'], 404);
        }

        if (!$force && $post->post_status !== 'trash') {
            $result = wp_trash_post($post_id);
        } else {
            $result = wp_delete_post($post_id, true);
        }

        if (!$result) {
            return new WP_REST_Response(['success' => false, 'error' => 'Failed to delete post.'], 500);
        }

        return new WP_REST_Response([
            'success' => true,
            'post_id' => $post_id,
            'status' => ($force || $post->post_status === 'trash') ? 'deleted' : 'trash'
        ], 200);
    }

    public function upload_media_handler(WP_REST_Request $request) {
        require_once(ABSPATH . 'wp-admin/includes/image.php');
        require_once(ABSPATH . 'wp-admin/includes/file.php');
        require_once(ABSPATH . 'wp-admin/includes/media.php');

        if (empty($_FILES['file'])) {
            return new WP_REST_Response(['success' => false, 'error' => 'No file uploaded'], 400);
        }

        if (!empty($_FILES['file']['size']) && $_FILES['file']['size'] > self::MEDIA_MAX_BYTES) {
            return new WP_REST_Response(['success' => false, 'error' => 'File size exceeds maximum limit of ' . self::MEDIA_MAX_MB . 'MB.'], 400);
        }

        // Validate multipart file signature body hash
        $file_hash = hash_file('sha256', $_FILES['file']['tmp_name']);
        $expected_hash = $_SERVER['HTTP_X_CONNECTMWP_BODY_HASH'] ?? $_SERVER['X_CONNECTMWP_BODY_HASH'] ?? '';
        if (empty($expected_hash)) {
            if (function_exists('getallheaders')) {
                $headers = getallheaders();
                foreach ($headers as $name => $value) {
                    if (strcasecmp($name, 'X-ConnectMWP-Body-Hash') === 0) {
                        $expected_hash = $value;
                        break;
                    }
                }
            }
        }

        if (empty($expected_hash) || !hash_equals($expected_hash, $file_hash)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Upload signature body hash verification failed.'], 401);
        }

        $attachment_id = media_handle_upload('file', 0);

        if (is_wp_error($attachment_id)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Failed to upload media.'], 500);
        }

        // Explicitly set media owner to bound user
        wp_update_post([
            'ID' => $attachment_id,
            'post_author' => $this->bound_user_id
        ]);

        return new WP_REST_Response([
            'success'       => true,
            'attachment_id' => $attachment_id,
            'url'           => wp_get_attachment_url($attachment_id),
        ], 200);
    }

    public function get_tags_handler(?WP_REST_Request $request = null) {
        $limit = self::DEFAULT_PER_PAGE;
        $offset = 0;
        $search = '';
        if ($request instanceof WP_REST_Request) {
            $limit = $request->get_param('limit') ? intval($request->get_param('limit')) : self::DEFAULT_PER_PAGE;
            $offset = $request->get_param('offset') ? intval($request->get_param('offset')) : 0;
            $search = $request->get_param('search') ? sanitize_text_field($request->get_param('search')) : '';
        }
        $limit = min(self::MAX_PER_PAGE, max(self::MIN_PER_PAGE, $limit));
        $offset = max(0, $offset);

        $args = [
            'hide_empty' => false,
            'number'     => $limit,
            'offset'     => $offset,
        ];
        if (!empty($search)) {
            $args['search'] = $search;
        }

        $tags = get_tags($args);
        $result = [];
        if (is_array($tags)) {
            foreach ($tags as $tag) {
                $result[] = [
                    'id'   => $tag->term_id,
                    'name' => $tag->name,
                    'slug' => $tag->slug,
                ];
            }
        }

        // T049: pagination parity with get_posts. Count the full filtered set
        // (same hide_empty + search as the listing, but no number/offset window)
        // so the AI client can paginate deterministically instead of over-fetching.
        $count_args = ['taxonomy' => 'post_tag', 'hide_empty' => false];
        if (!empty($search)) {
            $count_args['search'] = $search;
        }
        $count = wp_count_terms($count_args);
        $total = is_wp_error($count) ? count($result) : intval($count);
        $has_more = ($offset + count($result)) < $total;

        return new WP_REST_Response(['success' => true, 'tags' => $result, 'total' => $total, 'has_more' => $has_more], 200);
    }

    public function get_categories_handler(?WP_REST_Request $request = null) {
        $limit = self::DEFAULT_PER_PAGE;
        $offset = 0;
        $search = '';
        if ($request instanceof WP_REST_Request) {
            $limit = $request->get_param('limit') ? intval($request->get_param('limit')) : self::DEFAULT_PER_PAGE;
            $offset = $request->get_param('offset') ? intval($request->get_param('offset')) : 0;
            $search = $request->get_param('search') ? sanitize_text_field($request->get_param('search')) : '';
        }
        $limit = min(self::MAX_PER_PAGE, max(self::MIN_PER_PAGE, $limit));
        $offset = max(0, $offset);

        $args = [
            'hide_empty' => false,
            'number'     => $limit,
            'offset'     => $offset,
        ];
        if (!empty($search)) {
            $args['search'] = $search;
        }

        $categories = get_categories($args);
        $result = [];
        if (is_array($categories)) {
            foreach ($categories as $category) {
                $result[] = [
                    'id'   => $category->term_id,
                    'name' => $category->name,
                    'slug' => $category->slug,
                ];
            }
        }

        // T049: pagination parity with get_posts. Count the full filtered set
        // (same hide_empty + search as the listing, but no number/offset window)
        // so the AI client can paginate deterministically instead of over-fetching.
        $count_args = ['taxonomy' => 'category', 'hide_empty' => false];
        if (!empty($search)) {
            $count_args['search'] = $search;
        }
        $count = wp_count_terms($count_args);
        $total = is_wp_error($count) ? count($result) : intval($count);
        $has_more = ($offset + count($result)) < $total;

        return new WP_REST_Response(['success' => true, 'categories' => $result, 'total' => $total, 'has_more' => $has_more], 200);
    }

    public function create_category_handler(WP_REST_Request $request) {
        $params = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_body_params();
        }

        $name = !empty($params['name']) ? sanitize_text_field($params['name']) : '';
        $slug = !empty($params['slug']) ? sanitize_title($params['slug']) : '';
        $parent = !empty($params['parent']) ? intval($params['parent']) : 0;

        if (empty($name)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Name is required'], 400);
        }

        $args = [];
        if (!empty($slug)) {
            $args['slug'] = $slug;
        }
        if ($parent > 0) {
            $args['parent'] = $parent;
        }

        $term = wp_insert_term($name, 'category', $args);
        if (is_wp_error($term)) {
            // (T066) Do NOT echo the raw WP_Error to the client — it's the one
            // verbatim upstream-message passthrough in the codebase and a future
            // WP/filter could enrich it with internals. Operator gets detail in
            // the log; client gets a fixed, intent-revealing string.
            error_log('connectmwp: wp_insert_term(category) failed: ' . $term->get_error_message());
            return new WP_REST_Response(['success' => false, 'error' => 'Could not create the category (it may already exist).'], 400);
        }

        return new WP_REST_Response([
            'success' => true,
            'id' => $term['term_id'],
            'name' => $name
        ], 200);
    }

    public function create_tag_handler(WP_REST_Request $request) {
        $params = $request->get_json_params();
        if (empty($params)) {
            $params = $request->get_body_params();
        }

        $name = !empty($params['name']) ? sanitize_text_field($params['name']) : '';
        $slug = !empty($params['slug']) ? sanitize_title($params['slug']) : '';

        if (empty($name)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Name is required'], 400);
        }

        $args = [];
        if (!empty($slug)) {
            $args['slug'] = $slug;
        }

        $term = wp_insert_term($name, 'post_tag', $args);
        if (is_wp_error($term)) {
            // (T066) See create_category_handler — never echo the raw WP_Error.
            error_log('connectmwp: wp_insert_term(post_tag) failed: ' . $term->get_error_message());
            return new WP_REST_Response(['success' => false, 'error' => 'Could not create the tag (it may already exist).'], 400);
        }

        return new WP_REST_Response([
            'success' => true,
            'id' => $term['term_id'],
            'name' => $name
        ], 200);
    }

    /**
     * Admin-AJAX Handler (Fallback endpoint)
     */
    public function handle_ajax_request() {
        $action = isset($_REQUEST['connectmwp_action']) ? sanitize_key($_REQUEST['connectmwp_action']) : '';
        if (empty($action)) {
            wp_send_json_error(['error' => 'Missing action'], 400);
        }

        // Verify request signature
        if (!$this->verify_request_signature(null)) {
            $code = $this->verification_error_code ?: 'connectmwp_unauthorized';
            wp_send_json_error([
                'code'    => $code,
                'message' => $this->describe_verification_error($code),
            ], 401);
        }

        $request = new WP_REST_Request($_SERVER['REQUEST_METHOD']);
        foreach ($_REQUEST as $k => $v) {
            if ($k !== 'action' && $k !== 'connectmwp_action') {
                $request->set_param($k, $v);
            }
        }

        // Param injection that the dispatcher assumes is already on the request:
        // map the AJAX `post_id` field onto the canonical `id` param the
        // *_handler / check_* callbacks read (preserves the prior switch behavior).
        if (in_array($action, ['get_post', 'update_post', 'delete_post'], true)) {
            $request->set_param('id', isset($_REQUEST['post_id']) ? intval($_REQUEST['post_id']) : 0);
        }

        $res = $this->dispatch_action($action, $request);

        // Preserve the historical AJAX error-envelope shape byte-for-byte.
        // The legacy switch wrapped ONLY its two dispatch-GATE errors via
        // wp_send_json_error() -- a failed capability check (403 Forbidden) and
        // the unknown-action default (400 Invalid action) -- producing the
        // {success:false,data:{error:...}} envelope. EVERY handler-produced
        // response (success AND handler errors like 404/500, the in-handler
        // IDOR 403, upload/category/tag errors) fell through to wp_send_json()
        // and was emitted FLAT ({success:false,error:...}). dispatch_action()
        // flags only the gate path, so re-wrap that case and emit all else flat.
        if ($this->last_dispatch_gated) {
            wp_send_json_error(['error' => $res->get_data()['error']], $res->get_status());
        }

        wp_send_json($res->get_data(), $res->get_status());
    }

    /**
     * Transport-agnostic action dispatcher (T2). SSOT mapping of
     * action name -> capability check -> handler, shared by every transport
     * (AJAX today; MCP/JSON-RPC later). It does NOT touch $_REQUEST / $_SERVER,
     * does NOT emit output (no wp_send_json* / echo / exit), and does NOT
     * authenticate -- the CALLER is responsible for signature verification and
     * for having populated every handler param (e.g. `id`) on $request.
     *
     * @param string          $action  Sanitized action name.
     * @param WP_REST_Request $request Fully-populated request (params already set).
     * @return WP_REST_Response Handler result, or a forbidden/invalid envelope.
     */
    private function dispatch_action(string $action, WP_REST_Request $request): WP_REST_Response {
        // Reset on every call so a prior gate hit can't leak into this dispatch.
        // Set true ONLY on a dispatch-GATE early return (capability-check failure
        // or unknown-action default) -- never for a handler-produced response.
        $this->last_dispatch_gated = false;

        // Defense-in-depth auth guard: dispatch_action performs AUTHORIZATION
        // ONLY against $this->bound_user_id. Authentication is the caller's job
        // (handle_ajax_request -> verify_request_signature; the /mcp route's
        // permission_callback -> verify_token_request). If NEITHER auth path ran
        // for this request, or no real user got bound, refuse here so a future
        // caller that forgets to authenticate can never have us authorize against
        // a stale/zero user. Both existing callers authenticate first, so this
        // never trips in normal flow.
        if ($this->signature_verified !== true && $this->cgpt_token_verified !== true) {
            $this->last_dispatch_gated = true;
            return new WP_REST_Response(['success' => false, 'error' => 'Unauthorized'], 401);
        }
        if ($this->bound_user_id <= 0) {
            $this->last_dispatch_gated = true;
            return new WP_REST_Response(['success' => false, 'error' => 'Unauthorized'], 401);
        }

        switch ($action) {
            case 'get_posts':
                if (!$this->cap_can_read()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->get_posts_handler($request);
            case 'get_post':
                if (!$this->cap_can_read()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->get_post_handler($request);
            case 'create_post':
                if (!$this->cap_can_edit()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->create_post_handler($request);
            case 'update_post':
                if (!$this->cap_can_edit_post($request)) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->update_post_handler($request);
            case 'delete_post':
                if (!$this->cap_can_delete_post($request)) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->delete_post_handler($request);
            case 'upload_media':
                if (!$this->cap_can_upload()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->upload_media_handler($request);
            case 'get_tags':
                if (!$this->cap_can_read()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->get_tags_handler($request);
            case 'get_categories':
                if (!$this->cap_can_read()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->get_categories_handler($request);
            case 'create_category':
                if (!$this->cap_can_taxonomy()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->create_category_handler($request);
            case 'create_tag':
                if (!$this->cap_can_taxonomy()) { $this->last_dispatch_gated = true; return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403); }
                return $this->create_tag_handler($request);
            case 'whoami':
                // Signature already verified by the caller; no further capability required.
                return $this->whoami_handler($request);
            default:
                $this->last_dispatch_gated = true;
                return new WP_REST_Response(['success' => false, 'error' => 'Invalid action'], 400);
        }
    }

    // ========================================================================
    // REMOTE MCP (JSON-RPC 2.0) ENDPOINT — for ChatGPT and other HTTP MCP clients
    // ========================================================================
    // Single-response JSON-RPC over HTTP POST (NO SSE / streaming). Auth is the
    // bearer token enforced by verify_token_request (the route's
    // permission_callback); this handler never re-authenticates. Every tool call
    // runs through dispatch_action so capability checks + handlers are shared with
    // the signature/AJAX transports — there is NO duplicated publish/capability
    // logic here. The tools/list schema below is a SECOND definition of the tool
    // surface (the canonical first copy lives in connectmwp-mcp/index.js
    // setRequestHandler(ListToolsRequestSchema)); tool `name`s and inputSchema
    // field names MUST stay byte-aligned with that file so ChatGPT sees the SAME
    // tool surface Claude/Cursor see (a later task documents this contract).

    // Wire protocol version this server advertises when a client omits a usable
    // one. Matches a version negotiated by the @modelcontextprotocol/sdk used by
    // the stdio client and accepted by ChatGPT's MCP connector. The handler echoes
    // the client's requested version when present (per the MCP initialize spec),
    // falling back to this only when absent/non-string.
    const MCP_PROTOCOL_VERSION = '2025-06-18';

    /**
     * MCP tool-name -> internal dispatch_action name. SSOT for the mapping; both
     * tools/list (to expose the surface) and tools/call (to route execution) read
     * it so they can never drift from each other.
     */
    private function mcp_tool_action_map() {
        return [
            'connectmwp_get_posts'        => 'get_posts',
            'connectmwp_get_post'         => 'get_post',
            'connectmwp_create_post'      => 'create_post',
            'connectmwp_update_post'      => 'update_post',
            'connectmwp_delete_post'      => 'delete_post',
            // NOTE: connectmwp_upload_media is intentionally NOT exposed over the
            // remote MCP (ChatGPT) transport — it requires local file access that
            // JSON-RPC can't carry. Omitted from both this map and
            // mcp_tool_definitions(); a direct tools/call for it falls through to
            // the unknown-tool -32602 path. The upload_media action itself stays
            // reachable via the AJAX/signature transport (dispatch_action).
            'connectmwp_list_tags'        => 'get_tags',
            'connectmwp_list_categories'  => 'get_categories',
            'connectmwp_create_tag'       => 'create_tag',
            'connectmwp_create_category'  => 'create_category',
            'connectmwp_status'           => 'whoami',
        ];
    }

    /**
     * The MCP tool definitions advertised via tools/list. Mirrors
     * connectmwp-mcp/index.js EXACTLY (names + inputSchema field names). Kept as a
     * method (not inlined) so the shape is greppable and testable.
     */
    private function mcp_tool_definitions() {
        $site_prop = [
            'type'        => 'string',
            'description' => 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.',
        ];

        return [
            [
                'name'        => 'connectmwp_get_posts',
                'description' => 'Retrieve titles, content, URLs, and IDs of existing posts from the WordPress site.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'   => $site_prop,
                        'limit'  => ['type' => 'integer', 'description' => 'Maximum number of posts to retrieve (default 50)'],
                        'offset' => ['type' => 'integer', 'description' => 'Number of posts to offset (for pagination, default 0)'],
                        'fields' => ['type' => 'string', 'description' => 'Optional comma-separated list of fields to return (e.g. "id,title,content"). Defaults to excluding content to save bandwidth.'],
                    ],
                ],
            ],
            [
                'name'        => 'connectmwp_create_post',
                'description' => 'Create a new post draft or publish directly on a WordPress site.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'           => $site_prop,
                        'title'          => ['type' => 'string', 'description' => 'Title of the post'],
                        'content'        => ['type' => 'string', 'description' => 'Content of the post in clean HTML or Gutenberg block markup'],
                        'status'         => ['type' => 'string', 'enum' => ['draft', 'publish', 'trash', 'pending'], 'description' => 'Post status: draft (default for review), publish (direct; requires publish capability, else auto-downgraded to pending), pending (submit for review), or trash'],
                        'categories'     => ['type' => 'array', 'items' => ['type' => 'integer'], 'description' => 'List of category IDs to assign'],
                        'tags'           => ['type' => 'array', 'items' => ['type' => 'integer'], 'description' => 'List of tag IDs to assign (e.g. 1-5 tags)'],
                        'featured_media' => ['type' => 'integer', 'description' => 'ID of the uploaded media file to set as the Featured Image'],
                    ],
                    'required'   => ['title'],
                ],
            ],
            [
                'name'        => 'connectmwp_update_post',
                'description' => 'Update an existing post (e.g., to insert SEO internal links).',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'           => $site_prop,
                        'id'             => ['type' => 'integer', 'description' => 'WordPress Post ID to update'],
                        'title'          => ['type' => 'string', 'description' => 'New title'],
                        'content'        => ['type' => 'string', 'description' => 'New content body'],
                        'status'         => ['type' => 'string', 'enum' => ['draft', 'publish', 'trash', 'pending']],
                        'categories'     => ['type' => 'array', 'items' => ['type' => 'integer']],
                        'tags'           => ['type' => 'array', 'items' => ['type' => 'integer']],
                        'featured_media' => ['type' => 'integer'],
                    ],
                    'required'   => ['id'],
                ],
            ],
            // connectmwp_upload_media is deliberately omitted from tools/list — it
            // needs local file access and can't function over the remote MCP
            // (ChatGPT) JSON-RPC transport. It remains available via the local
            // MCP client (Claude/Cursor) over the AJAX/signature path.
            [
                'name'        => 'connectmwp_list_tags',
                'description' => 'List all tags on the WordPress site to select the 1-5 most relevant ones.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'   => $site_prop,
                        'limit'  => ['type' => 'integer', 'description' => 'Maximum number of tags to retrieve (default 50, max 200)'],
                        'offset' => ['type' => 'integer', 'description' => 'Number of tags to offset (default 0)'],
                        'search' => ['type' => 'string', 'description' => 'Optional search term to filter tags by name'],
                    ],
                ],
            ],
            [
                'name'        => 'connectmwp_list_categories',
                'description' => 'List all categories on the WordPress site.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'   => $site_prop,
                        'limit'  => ['type' => 'integer', 'description' => 'Maximum number of categories to retrieve (default 50, max 200)'],
                        'offset' => ['type' => 'integer', 'description' => 'Number of categories to offset (default 0)'],
                        'search' => ['type' => 'string', 'description' => 'Optional search term to filter categories by name'],
                    ],
                ],
            ],
            [
                'name'        => 'connectmwp_get_post',
                'description' => 'Retrieve full details of a single post by ID (to analyze link opportunities).',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'   => $site_prop,
                        'id'     => ['type' => 'integer', 'description' => 'WordPress Post ID to retrieve'],
                        'fields' => ['type' => 'string', 'description' => 'Optional comma-separated list of fields to return (e.g. "id,title,content,url").'],
                    ],
                    'required'   => ['id'],
                ],
            ],
            [
                'name'        => 'connectmwp_create_category',
                'description' => 'Create a new category on the WordPress site.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'   => $site_prop,
                        'name'   => ['type' => 'string', 'description' => 'Category name'],
                        'slug'   => ['type' => 'string', 'description' => 'Optional URL-friendly slug for the category'],
                        'parent' => ['type' => 'integer', 'description' => 'Optional parent category ID'],
                    ],
                    'required'   => ['name'],
                ],
            ],
            [
                'name'        => 'connectmwp_create_tag',
                'description' => 'Create a new tag on the WordPress site.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site' => $site_prop,
                        'name' => ['type' => 'string', 'description' => 'Tag name'],
                        'slug' => ['type' => 'string', 'description' => 'Optional URL-friendly slug for the tag'],
                    ],
                    'required'   => ['name'],
                ],
            ],
            [
                'name'        => 'connectmwp_delete_post',
                'description' => 'Trash or permanently delete a post by ID from the WordPress site.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site'  => $site_prop,
                        'id'    => ['type' => 'integer', 'description' => 'WordPress Post ID to delete'],
                        'force' => ['type' => 'boolean', 'description' => 'Optional. If true, bypasses trash and permanently deletes the post. Default false.'],
                    ],
                    'required'   => ['id'],
                ],
            ],
            [
                'name'        => 'connectmwp_status',
                'description' => 'Show connectMWP version and connection status: the running local MCP client version, the paired sites, the default site, and — via a live signed round-trip — the connectMWP plugin version installed on the target WordPress site. Use to confirm which versions are running and that end-to-end signing works.',
                'inputSchema' => [
                    'type'       => 'object',
                    'properties' => [
                        'site' => $site_prop,
                    ],
                ],
            ],
        ];
    }

    /**
     * Build a JSON-RPC 2.0 error envelope as a WP_REST_Response (HTTP 200 — the
     * error rides in-band per JSON-RPC). $id may be null for pre-parse failures.
     */
    private function mcp_jsonrpc_error($id, $code, $message) {
        return new WP_REST_Response([
            'jsonrpc' => '2.0',
            'id'      => $id,
            'error'   => ['code' => $code, 'message' => $message],
        ], 200);
    }

    /**
     * Build a JSON-RPC 2.0 success envelope as a WP_REST_Response (HTTP 200).
     */
    private function mcp_jsonrpc_result($id, $result) {
        return new WP_REST_Response([
            'jsonrpc' => '2.0',
            'id'      => $id,
            'result'  => $result,
        ], 200);
    }

    /**
     * Remote MCP JSON-RPC 2.0 endpoint handler. Auth already enforced by
     * verify_token_request (permission_callback) which set $this->bound_user_id.
     */
    public function mcp_handler(WP_REST_Request $request): WP_REST_Response {
        // Belt-and-suspenders: central_rest_auth already emitted no-cache for the
        // namespace, but re-assert here so a future refactor of the filter can't
        // silently let an edge cache store a token-authenticated MCP response.
        $this->send_rest_nocache_headers();

        // Bound parse cost on this token-authenticated route: reject oversized
        // bodies before JSON decoding. JSON-RPC envelopes carry text only (no file
        // bytes), so MCP_MAX_BODY_BYTES (2 MB) comfortably covers any real post.
        if (strlen($request->get_body()) > self::MCP_MAX_BODY_BYTES) {
            return $this->mcp_jsonrpc_error(null, -32700, 'Request body too large.');
        }

        $body = $request->get_json_params();

        // Batch arrays are not supported — reject with a clear JSON-RPC error
        // rather than silently processing the first element. (A JSON array decodes
        // to a list; a single request object decodes to an associative array.)
        if (is_array($body) && array_key_exists(0, $body)) {
            return $this->mcp_jsonrpc_error(null, -32600, 'Batch requests are not supported. Send a single JSON-RPC request object.');
        }

        // Parse failure / non-object envelope.
        if (!is_array($body) || empty($body)) {
            return $this->mcp_jsonrpc_error(null, -32700, 'Parse error: request body is not a valid JSON-RPC object.');
        }

        // id may legitimately be null (notification) — only absent for notifications.
        $id     = array_key_exists('id', $body) ? $body['id'] : null;
        $method = isset($body['method']) && is_string($body['method']) ? $body['method'] : '';
        $params = isset($body['params']) && is_array($body['params']) ? $body['params'] : [];

        if (!isset($body['jsonrpc']) || $body['jsonrpc'] !== '2.0') {
            return $this->mcp_jsonrpc_error($id, -32600, 'Invalid Request: "jsonrpc" must be "2.0".');
        }

        if ($method === '') {
            return $this->mcp_jsonrpc_error($id, -32600, 'Invalid Request: missing "method".');
        }

        switch ($method) {
            case 'initialize':
                // Echo the client's requested protocol version when it's a usable
                // string (per the MCP initialize spec), else advertise our default.
                $requested = isset($params['protocolVersion']) && is_string($params['protocolVersion']) && $params['protocolVersion'] !== ''
                    ? $params['protocolVersion']
                    : self::MCP_PROTOCOL_VERSION;
                return $this->mcp_jsonrpc_result($id, [
                    'protocolVersion' => $requested,
                    'capabilities'    => ['tools' => (object) []],
                    'serverInfo'      => [
                        'name'    => 'connectmwp',
                        'version' => self::version(),
                    ],
                ]);

            case 'notifications/initialized':
                // A notification carries no id and per JSON-RPC gets NO response
                // body. Return an empty 200 so HTTP clients see a clean ack without
                // a JSON-RPC envelope they'd try (and fail) to correlate to an id.
                $resp = new WP_REST_Response(null, 200);
                return $resp;

            case 'ping':
                return $this->mcp_jsonrpc_result($id, (object) []);

            case 'tools/list':
                return $this->mcp_jsonrpc_result($id, ['tools' => $this->mcp_tool_definitions()]);

            case 'tools/call':
                return $this->mcp_handle_tools_call($id, $params);

            default:
                // Sanitize+truncate the caller-supplied method before echoing it
                // (hygiene — JSON, not HTML, so this is not XSS).
                $safe_method = substr(preg_replace('/[^a-zA-Z0-9_\/]/', '', $method), 0, 64);
                return $this->mcp_jsonrpc_error($id, -32601, 'Method not found: ' . $safe_method);
        }
    }

    /**
     * Execute an MCP tools/call: map the tool name to an internal action, marshal
     * arguments onto a fresh WP_REST_Request, run dispatch_action (which performs
     * the per-action capability check using the token-bound user), and convert the
     * WP_REST_Response into an MCP tool result. Capability/handler errors are
     * conveyed via isError=true at the JSON-RPC RESULT layer (HTTP+JSON-RPC stay
     * 200) per MCP convention — only protocol-level faults use JSON-RPC `error`.
     */
    private function mcp_handle_tools_call($id, $params): WP_REST_Response {
        $name = isset($params['name']) && is_string($params['name']) ? $params['name'] : '';
        $arguments = isset($params['arguments']) && is_array($params['arguments']) ? $params['arguments'] : [];

        $map = $this->mcp_tool_action_map();
        if ($name === '' || !isset($map[$name])) {
            // Unknown / missing tool name is an invalid-params protocol fault.
            // Sanitize+truncate the caller-supplied name before echoing it
            // (hygiene — JSON, not HTML, so this is not XSS).
            $safe_name = $name !== '' ? substr(preg_replace('/[^a-zA-Z0-9_]/', '', $name), 0, 64) : '(missing)';
            return $this->mcp_jsonrpc_error($id, -32602, 'Unknown tool: ' . $safe_name);
        }
        $action = $map[$name];

        // Marshal the MCP arguments onto a fresh request. The mutating handlers
        // (create/update/delete_post, create_category, create_tag) read params via
        // get_json_params()->get_body_params(); set both the JSON body+header (so
        // get_json_params() parses it) AND set_param for each key (so id-style
        // ArrayAccess reads and the read/list handlers' get_param() resolve too).
        // The `site` argument is client-side routing only — it never reaches a
        // handler, so dropping it here is harmless.
        $req = new WP_REST_Request('POST', '/' . self::API_NAMESPACE . '/mcp');
        $json_payload = [];
        foreach ($arguments as $k => $v) {
            if ($k === 'site') {
                continue;
            }
            $json_payload[$k] = $v;
            $req->set_param($k, $v);
        }
        $req->set_header('Content-Type', 'application/json');
        $req->set_body(wp_json_encode($json_payload));

        // get/update/delete_post read intval($request['id']); dispatch_action's
        // contract is that `id` is already on the request. set_param above covers
        // it, but be explicit so an absent id still lands as a param the handler
        // can read (it'll 404 cleanly rather than mis-resolving).
        if (in_array($action, ['get_post', 'update_post', 'delete_post'], true)) {
            $req->set_param('id', isset($arguments['id']) ? intval($arguments['id']) : 0);
        }

        // Defense-in-depth: upload_media is no longer in mcp_tool_action_map(), so
        // it can't be reached here (a tools/call for it falls through to the
        // unknown-tool -32602 path above). This guard stays as a belt-and-suspenders
        // catch in case the mapping is ever re-added — upload_media reads $_FILES,
        // which an HTTP JSON-RPC call cannot carry.
        if ($action === 'upload_media') {
            return $this->mcp_tool_error_result($id, 'Media upload is not supported over the remote MCP (ChatGPT) endpoint — it requires local file access. Use a local MCP client (Claude/Cursor) for connectmwp_upload_media.');
        }

        $response = $this->dispatch_action($action, $req);
        $data     = $response->get_data();
        $status   = $response->get_status();

        if ($status >= 200 && $status < 300) {
            return $this->mcp_jsonrpc_result($id, [
                'content' => [['type' => 'text', 'text' => wp_json_encode($data)]],
                'isError' => false,
            ]);
        }

        // Non-2xx: surface the handler/capability error text the handlers already
        // produce (they never embed internals — see the T066 sanitization notes).
        $message = is_array($data) && isset($data['error']) ? $data['error'] : 'Tool execution failed.';
        return $this->mcp_tool_error_result($id, $message);
    }

    /**
     * MCP tool-error result: isError=true with the message as text content. Stays
     * a JSON-RPC SUCCESS envelope (HTTP 200) — the error is in-band per MCP spec.
     */
    private function mcp_tool_error_result($id, $message): WP_REST_Response {
        return $this->mcp_jsonrpc_result($id, [
            'content' => [['type' => 'text', 'text' => is_string($message) ? $message : wp_json_encode($message)]],
            'isError' => true,
        ]);
    }

    /**
     * Add Settings Page under Settings menu
     */
    public function add_settings_page() {
        add_options_page(
            'connectMWP Settings',
            'connectMWP',
            'manage_options',
            'connectmwp',
            [$this, 'render_settings_page']
        );
    }

    /**
     * Pure status classifier for a paired client (T055). SSOT for the
     * "is this client just-paired / stale?" business rules so the policy lives in
     * one testable place instead of inline in the render loop. No I/O, no globals.
     *
     * @param int|false   $created_ts    Unix ts of pairing, or false if unparsable.
     * @param int|false   $last_used_ts  Unix ts of last use, or false.
     * @param string      $last_used_raw Raw last_used string ('' / 'never' => unused).
     * @param int         $now           Current Unix ts.
     * @return array{is_just_paired:bool,is_stale:bool}
     */
    private function classify_key_status($created_ts, $last_used_ts, $last_used_raw, $now) {
        $age_created   = $created_ts   ? ($now - $created_ts)   : 0;
        $age_last_used = $last_used_ts ? ($now - $last_used_ts) : null;
        $never_used    = empty($last_used_raw);

        $is_just_paired = (bool) ($created_ts && $age_created < self::JUST_PAIRED_SECONDS);
        $is_stale = ($never_used && $age_created > self::STALE_UNUSED_SECONDS) ||
                    ($age_last_used !== null && $age_last_used > self::STALE_LAST_USED_SECONDS);

        return [
            'is_just_paired' => $is_just_paired,
            'is_stale'       => (bool) $is_stale,
        ];
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient privileges to access this page.'));
        }

        // Process revocation of keys
        if (isset($_POST['connectmwp_action']) && $_POST['connectmwp_action'] === 'revoke_key' && isset($_POST['key_id'])) {
            check_admin_referer('connectmwp_revoke_key');
            $key_id_to_revoke = sanitize_text_field($_POST['key_id']);
            // Confirm existence first so the success notice stays accurate, then
            // delete the per-key row + index entry + legacy fallback (T039 DAL).
            if ($this->get_key($key_id_to_revoke) !== false) {
                $this->delete_key($key_id_to_revoke);
                echo '<div class="notice notice-success is-dismissible"><p>Client key successfully revoked.</p></div>';
            }
        }

        // Process generation of pairing code
        if (isset($_POST['connectmwp_action']) && $_POST['connectmwp_action'] === 'generate_pairing') {
            check_admin_referer('connectmwp_generate_pairing');
            $this->generate_enrollment_code();
        }

        // Process the "behind trusted proxy" setting (T041). Single write site
        // for the connectmwp_trust_proxy option; is_behind_trusted_proxy() is the
        // single read site.
        if (isset($_POST['connectmwp_action']) && $_POST['connectmwp_action'] === 'set_trust_proxy') {
            check_admin_referer('connectmwp_proxy_setting');
            update_option('connectmwp_trust_proxy', !empty($_POST['connectmwp_trust_proxy']));
            echo '<div class="notice notice-success is-dismissible"><p>Trusted-proxy setting saved.</p></div>';
        }

        // Retrieve active pairing code if it exists and hasn't expired
        $enrollment_string = '';
        $stored = get_option('connectmwp_enrollment_code');
        if (is_array($stored) && !empty($stored['code']) && time() <= intval($stored['expires'])) {
            $enrollment_string = esc_url(home_url()) . ',' . $stored['code'];
        }

        // Source keys via the DAL (T039 SSOT) and resolve bound users with a
        // single batched query instead of one get_userdata() per key (T043 N+1
        // fix). `fields` is intentionally omitted so each WP_User exposes
        // ->roles directly (WP batches the role meta load) — keeping the table
        // output byte-identical while collapsing N user lookups into ONE query.
        $all_keys = $this->list_keys();
        $user_ids = array_values(array_unique(array_filter(array_map(function ($k) {
            return intval($k['bound_user_id']);
        }, $all_keys))));
        $user_map = [];
        if (!empty($user_ids)) {
            foreach (get_users(['include' => $user_ids]) as $u) {
                $user_map[intval($u->ID)] = $u;
            }
        }

        $all_keys_with_users = [];
        foreach ($all_keys as $key_id => $key_data) {
            $user_info = $user_map[intval($key_data['bound_user_id'])] ?? null;
            $key_data['user_login']   = $user_info ? $user_info->user_login : 'Unknown User';
            $key_data['user_display'] = $user_info ? ($user_info->display_name ?: $user_info->user_login) : 'Unknown User';
            $key_data['user_roles']   = $user_info && is_array($user_info->roles) ? array_values($user_info->roles) : [];
            $key_data['key_id']       = $key_id;
            $all_keys_with_users[]    = $key_data;
        }

        // Newest first — so the most recent pairing is immediately visible and
        // can be flagged in the table.
        usort($all_keys_with_users, function($a, $b) {
            return strcmp($b['created'] ?? '', $a['created'] ?? '');
        });

        // Per-key enrichment: parse `created` and `last_used` (which come from
        // `current_time('mysql')` and carry NO timezone marker) with wp_timezone()
        // so the resulting Unix timestamps are correct regardless of how the
        // WP-configured timezone relates to the PHP-server timezone. Then derive
        // formatted display strings, a "just paired" flag (< 1 hour old, drives
        // the JUST PAIRED badge + the What now? panel), and a "stale" flag
        // (never used + > 7d old, OR last used > 30d ago — drives the grey dot).
        $now = time();
        foreach ($all_keys_with_users as &$k) {
            $k['display_created']    = $k['created']   ?? '';
            $k['display_last_used']  = !empty($k['last_used']) ? $k['last_used'] : 'never';
            $k['created_ts']         = false;
            $k['last_used_ts']       = false;
            if (function_exists('wp_timezone')) {
                $tz = wp_timezone();
                if (!empty($k['created'])) {
                    $dt = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $k['created'], $tz);
                    if ($dt instanceof DateTimeImmutable) {
                        $k['created_ts']      = $dt->getTimestamp();
                        $k['display_created'] = $dt->format('Y-m-d H:i');
                    }
                }
                if (!empty($k['last_used'])) {
                    $dt = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $k['last_used'], $tz);
                    if ($dt instanceof DateTimeImmutable) {
                        $k['last_used_ts']      = $dt->getTimestamp();
                        $k['display_last_used'] = $dt->format('Y-m-d H:i');
                    }
                }
            }
            $status = $this->classify_key_status($k['created_ts'], $k['last_used_ts'], $k['last_used'], $now);
            $k['is_just_paired'] = $status['is_just_paired'];
            $k['is_stale']       = $status['is_stale'];
        }
        unset($k);

        $most_recent   = !empty($all_keys_with_users) ? $all_keys_with_users[0] : null;
        $show_what_now = $most_recent && !empty($most_recent['is_just_paired']);

        // Three render states drive layout choice. mid-pair takes precedence
        // because the pairing card needs to lead during the 10-min window.
        if ($enrollment_string) {
            $page_state = 'mid-pair';
        } elseif (empty($all_keys_with_users)) {
            $page_state = 'zero';
        } else {
            $page_state = 'paired';
        }

        ?>
        <style>
            /* connectMWP plugin settings page — v2.0.18 redesign.
               Calm, status-first device-management aesthetic. All classes prefixed
               with cmwp- so the WP admin global CSS can't reach in. */
            .cmwp-wrap { max-width: 900px; margin: 20px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif; color: #2c3e50; }

            /* Hero */
            .cmwp-hero { background: linear-gradient(135deg, #2c3e50, #3498db); padding: 28px 32px; border-radius: 14px; color: #fff; box-shadow: 0 4px 14px rgba(44, 62, 80, 0.10); position: relative; overflow: hidden; margin-bottom: 24px; }
            .cmwp-hero::after { content: ''; position: absolute; right: -40px; top: -40px; width: 180px; height: 180px; border-radius: 50%; background: rgba(255,255,255,0.04); }
            .cmwp-hero h1 { margin: 0 0 8px 0; font-size: 26px; font-weight: 700; letter-spacing: -0.2px; display: flex; align-items: center; gap: 12px; color: #fff; }
            .cmwp-ver { font-size: 12px; font-weight: 500; opacity: 0.85; background: rgba(255,255,255,0.18); padding: 3px 10px; border-radius: 999px; letter-spacing: 0.3px; }
            .cmwp-hero p { margin: 0; font-size: 14px; opacity: 0.85; max-width: 560px; line-height: 1.5; }

            /* Card primitive */
            .cmwp-card { background: #fff; border: 1px solid #e5eaed; border-radius: 12px; padding: 22px 24px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(44, 62, 80, 0.03); }
            .cmwp-card-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 14px; }
            .cmwp-card-title { margin: 0; font-size: 16px; font-weight: 700; color: #2c3e50; letter-spacing: -0.1px; }
            .cmwp-card-sub { margin: 4px 0 0 0; font-size: 13px; color: #7f8c8d; line-height: 1.5; }

            /* Client list — the centerpiece. */
            .cmwp-client-list { display: grid; gap: 0; margin-top: 4px; border-radius: 8px; overflow: hidden; border: 1px solid #eef2f4; }
            .cmwp-client-row { display: grid; grid-template-columns: 1fr auto; grid-template-rows: auto auto;
                /* Explicit areas so the action button can't auto-place into the wide
                   left column (CSS Grid gotcha: row-pinned + auto-column items
                   fill row L→R, which would push the label rightward). */
                grid-template-areas: "label action" "meta action";
                align-items: center; column-gap: 14px; row-gap: 4px; padding: 14px 16px; background: #fff; transition: background 0.15s ease; }
            .cmwp-client-row + .cmwp-client-row { border-top: 1px solid #eef2f4; }
            .cmwp-client-row:nth-child(even) { background: #fbfcfd; }
            .cmwp-client-row:hover { background: #f5f9fc; }
            .cmwp-client-label { grid-area: label; font-size: 14.5px; font-weight: 700; color: #2c3e50; line-height: 1.3; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
            .cmwp-client-dot { width: 10px; height: 10px; border-radius: 50%; background: #16a085; box-shadow: 0 0 0 3px #d8f1ea; flex-shrink: 0; }
            .cmwp-client-dot.stale { background: #abb2b9; box-shadow: 0 0 0 3px #ecf0f1; }
            .cmwp-badge-new { display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 0.6px; color: #16a085; background: #d8f1ea; padding: 2px 7px; border-radius: 999px; }
            .cmwp-client-meta { grid-area: meta; color: #7f8c8d; padding-left: 20px; }
            .cmwp-meta-times { display: block; font-size: 12.5px; line-height: 1.55; }
            .cmwp-meta-key { display: block; margin-top: 3px; font-size: 11.5px; line-height: 1.4; }
            .cmwp-client-meta b { white-space: nowrap; color: #34495e; }
            .cmwp-meta-key code { font-family: SF Mono, Menlo, Consolas, monospace; font-size: 11.5px; color: #abb2b9; background: rgba(0,0,0,0.04); padding: 1px 6px; border-radius: 4px; white-space: nowrap; cursor: pointer; transition: background 0.15s ease, color 0.15s ease; }
            .cmwp-meta-key code:hover { background: rgba(52, 152, 219, 0.12); color: #2980b9; }
            .cmwp-meta-sep { color: #abb2b9; margin: 0 6px; }
            .cmwp-client-action { grid-area: action; align-self: center; justify-self: end; }
            .cmwp-tz-note { margin-top: 12px; font-size: 12px; color: #7f8c8d; }

            /* Buttons */
            .cmwp-btn-revoke { color: #c0392b; background: #fff; border: 1px solid #e5eaed; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; transition: background 0.15s ease, border-color 0.15s ease; }
            .cmwp-btn-revoke:hover { background: #fcebe9; border-color: #c0392b; }
            .cmwp-btn-pair-another { background: #3498db; border: none; color: #fff; padding: 7px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; box-shadow: 0 2px 4px rgba(52, 152, 219, 0.2); }
            .cmwp-btn-pair-another:hover { background: #2980b9; }
            .cmwp-btn-primary-large { background: #3498db; border: none; color: #fff; padding: 12px 28px; border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer; box-shadow: 0 4px 10px rgba(52, 152, 219, 0.25); }
            .cmwp-btn-primary-large:hover { background: #2980b9; }
            .cmwp-btn-copy { background: #34495e; color: #fff; border: none; border-radius: 6px; padding: 0 14px; font-size: 12px; font-weight: 600; cursor: pointer; }
            .cmwp-btn-copy:hover { background: #2c3e50; }

            /* Get Started — zero-state */
            .cmwp-getstarted { background: linear-gradient(180deg, #fff, #fbfcfd); border: 1px solid #e5eaed; border-radius: 14px; padding: 36px 32px 32px; text-align: center; margin-bottom: 18px; }
            .cmwp-step-tag { display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: 1px; color: #3498db; background: #ebf5fb; padding: 4px 12px; border-radius: 999px; text-transform: uppercase; }
            .cmwp-getstarted h2 { margin: 14px 0 8px 0; font-size: 22px; font-weight: 700; color: #2c3e50; letter-spacing: -0.3px; }
            .cmwp-getstarted p { margin: 0 auto 22px; max-width: 460px; font-size: 14px; color: #7f8c8d; line-height: 1.55; }

            /* Pairing-code card (mid-pair state) */
            .cmwp-pairing-card { background: #fff; border: 1px solid #e5eaed; border-left: 5px solid #f39c12; border-radius: 12px; padding: 22px 24px; margin-bottom: 18px; box-shadow: 0 4px 14px rgba(243, 156, 18, 0.10); }
            .cmwp-pc-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
            .cmwp-pc-head h2 { margin: 0; font-size: 16px; font-weight: 700; color: #b9770e; }
            .cmwp-pc-badges { display: flex; gap: 8px; }
            .cmwp-pc-badge { font-size: 11px; font-weight: 700; letter-spacing: 0.6px; padding: 3px 9px; border-radius: 999px; text-transform: uppercase; }
            .cmwp-pc-badge.timer { background: #fef3e0; color: #b9770e; }
            .cmwp-pc-badge.type { background: #fdebe1; color: #c0392b; }
            .cmwp-pc-instructions { background: #fafbfc; border: 1px solid #eef2f4; border-left: 3px solid #3498db; border-radius: 8px; padding: 12px 16px; margin-bottom: 14px; font-size: 13px; color: #34495e; line-height: 1.6; }
            .cmwp-pc-instructions ol { margin: 4px 0 0 0; padding-left: 20px; }
            .cmwp-pc-cmd { display: flex; gap: 8px; align-items: stretch; margin-bottom: 4px; }
            /* WP admin's `.wrap textarea` rule otherwise outranks ours and the npx command
               renders white-on-white. Boost specificity + !important. */
            .cmwp-wrap textarea.cmwp-pc-textarea { flex: 1; background: #1f2d3d !important; color: #ecf0f1 !important; border: none; border-radius: 6px; padding: 12px 14px; font-family: SF Mono, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.5; resize: none; height: 56px; }

            /* What now? panel */
            .cmwp-whatnow { background: #fefcf2; border: 1px solid #faedc5; border-left: 4px solid #f39c12; border-radius: 12px; padding: 18px 22px; margin-bottom: 18px; }
            .cmwp-whatnow h3 { margin: 0 0 8px 0; font-size: 14px; font-weight: 700; color: #b9770e; display: flex; align-items: center; gap: 8px; }
            .cmwp-whatnow ol { margin: 0; padding-left: 20px; font-size: 13px; color: #5d4e34; line-height: 1.65; }
            .cmwp-whatnow ol li { margin-bottom: 4px; }
            .cmwp-whatnow code { background: rgba(0,0,0,0.06); padding: 1px 6px; border-radius: 3px; font-size: 12px; }

            /* Configure card — tinted reference surface */
            .cmwp-config-card { background: #f6f9fc; border: 1px solid #e1ecf4; border-radius: 12px; padding: 22px 24px; }
            .cmwp-config-card .cmwp-card-title { font-size: 15px; }
            .cmwp-config-card .cmwp-card-sub { font-size: 12.5px; }
            .cmwp-tabs { display: flex; gap: 4px; border-bottom: 1px solid #d8e3ec; margin: 14px 0 16px; flex-wrap: wrap; }
            .cmwp-tab { padding: 8px 14px; font-size: 13px; font-weight: 600; color: #7f8c8d; cursor: pointer; background: none; border: none; border-bottom: 2px solid transparent; margin-bottom: -1px; transition: color 0.15s ease, border-color 0.15s ease; user-select: none; font-family: inherit; }
            .cmwp-tab.active { color: #3498db; border-bottom-color: #3498db; }
            .cmwp-tab:hover:not(.active) { color: #34495e; }
            .cmwp-tab:focus-visible { outline: 2px solid #3498db; outline-offset: 2px; border-radius: 4px; }
            .cmwp-tab-tip { font-size: 12px; color: #7f8c8d; line-height: 1.55; margin-bottom: 10px; }
            .cmwp-tab-tip b { color: #3498db; }
            .cmwp-config-json { background: #fff; border: 1px solid #dbe5ed; border-radius: 8px; padding: 12px 16px; font-family: SF Mono, Menlo, Consolas, monospace; font-size: 12px; color: #2c3e50; line-height: 1.55; overflow-x: auto; margin: 0; }
            .cmwp-config-json .cmwp-dim { color: #abb2b9; }
            .cmwp-config-json .cmwp-hi { background: #eaf3fb; border-left: 3px solid #3498db; padding: 2px 6px; display: inline-block; border-radius: 3px; font-weight: 700; color: #1f618d; }

            /* Responsive */
            @media (max-width: 600px) {
                .cmwp-wrap { padding: 0 12px; margin: 16px auto; }
                .cmwp-hero { padding: 22px 22px; }
                .cmwp-hero h1 { font-size: 22px; flex-wrap: wrap; }
                .cmwp-card { padding: 18px 18px; }
                .cmwp-client-row { grid-template-columns: 1fr; grid-template-areas: "label" "meta" "action"; row-gap: 8px; }
                .cmwp-client-action { justify-self: start; }
                .cmwp-pc-cmd { flex-direction: column; }
                .cmwp-wrap textarea.cmwp-pc-textarea { height: 70px; }
                .cmwp-btn-copy { height: 38px; padding: 0 16px; }
            }

            /* --- client-first switchboard: top-level tabs by client family --- */
            .cmwp-switch { background: #fff; border: 1px solid #e5eaed; border-radius: 14px; box-shadow: 0 1px 2px rgba(44,62,80,.03); padding: 18px 22px 6px; margin-bottom: 18px; }
            .cmwp-switch-q b { font-size: 15px; font-weight: 700; color: #2c3e50; }
            .cmwp-switch-q span { display: block; font-size: 12.5px; color: #7f8c8d; margin-top: 3px; line-height: 1.5; }
            .cmwp-ctabs { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 14px; }
            .cmwp-ctab { appearance: none; text-align: left; cursor: pointer; background: #fbfcfd; border: 1.5px solid #e5eaed; border-radius: 11px; padding: 13px 14px; transition: border-color .15s ease, background .15s ease, box-shadow .15s ease; font-family: inherit; display: flex; gap: 11px; align-items: flex-start; }
            .cmwp-ctab:hover { border-color: #cfe0ee; background: #fff; }
            .cmwp-ctab.active { border-color: #3498db; background: #fff; box-shadow: 0 3px 10px rgba(52,152,219,.13); }
            .cmwp-ctab:focus-visible { outline: 2px solid #3498db; outline-offset: 2px; }
            .cmwp-ctab-ic { width: 30px; height: 30px; border-radius: 8px; flex: 0 0 auto; display: grid; place-items: center; font-size: 16px; background: #ebf5fb; }
            .cmwp-ctab.active .cmwp-ctab-ic { background: #3498db; }
            .cmwp-ctab-nm { font-size: 13.5px; font-weight: 700; color: #2c3e50; line-height: 1.25; display: block; }
            .cmwp-ctab-mh { font-size: 11.5px; color: #7f8c8d; margin-top: 3px; font-weight: 600; display: block; }
            .cmwp-ctab.active .cmwp-ctab-mh { color: #2980b9; }
            .cmwp-panel { display: none; }
            .cmwp-panel.active { display: block; }
            .cmwp-stdio-where { font-size: 12.5px; color: #7f8c8d; line-height: 1.6; margin: 6px 0 0; }
            .cmwp-stdio-where code { background: rgba(0,0,0,.05); padding: 1px 6px; border-radius: 4px; font-size: 11.5px; }
            @media (max-width: 600px) { .cmwp-ctabs { grid-template-columns: 1fr; } }

            /* Merged "Your connections" table (one place for every connection type) */
            .cmwp-conns { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
            .cmwp-conns th { text-align: left; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.5px; color: #7f8c8d; padding: 7px 10px; border-bottom: 1px solid #eef2f4; font-weight: 700; }
            .cmwp-conns td { padding: 11px 10px; border-bottom: 1px solid #f4f7f9; color: #34495e; vertical-align: middle; }
            .cmwp-conns tr:last-child td { border-bottom: none; }
            .cmwp-ty { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; white-space: nowrap; }
            .cmwp-ty-key { background: #eef4fb; color: #2980b9; }
            .cmwp-ty-tok { background: #f3eefb; color: #7d3cba; }
            .cmwp-ty-oauth { background: #e9f7f2; color: #16a085; }
            .cmwp-conn-who { font-weight: 700; color: #2c3e50; }
            .cmwp-conn-sub { display: block; font-weight: 500; margin-top: 2px; }
            .cmwp-conn-sub code { font-family: SF Mono, Menlo, Consolas, monospace; font-size: 11px; color: #abb2b9; background: rgba(0,0,0,0.04); padding: 1px 6px; border-radius: 4px; cursor: pointer; }
            .cmwp-conn-sub code:hover { background: rgba(52,152,219,0.12); color: #2980b9; }
            .cmwp-stat { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: #16a085; }
            .cmwp-stat-dot { width: 8px; height: 8px; border-radius: 50%; background: #16a085; box-shadow: 0 0 0 3px #d8f1ea; flex-shrink: 0; }
            .cmwp-stat.stale { color: #7f8c8d; }
            .cmwp-stat.stale .cmwp-stat-dot { background: #abb2b9; box-shadow: 0 0 0 3px #ecf0f1; }
            .cmwp-conns form { margin: 0; }
            @media (max-width: 640px) {
                .cmwp-conns thead { display: none; }
                .cmwp-conns, .cmwp-conns tbody, .cmwp-conns tr, .cmwp-conns td { display: block; width: 100%; }
                .cmwp-conns tr { border: 1px solid #eef2f4; border-radius: 10px; margin-bottom: 10px; padding: 6px 4px; }
                .cmwp-conns td { border: none; padding: 6px 10px; }
            }
        </style>

        <script>
        function showConnectMWPToast(button, message) {
            let toast = document.getElementById('connectmwp-global-toast');
            if (!toast) {
                toast = document.createElement('div');
                toast.id = 'connectmwp-global-toast';
                toast.style.position = 'absolute';
                toast.style.padding = '6px 12px';
                toast.style.borderRadius = '6px';
                toast.style.fontSize = '12px';
                toast.style.fontWeight = '600';
                toast.style.color = '#fff';
                toast.style.background = '#2e7d32';
                toast.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)';
                toast.style.pointerEvents = 'none';
                toast.style.transition = 'opacity 0.2s ease-in-out';
                toast.style.zIndex = '99999';
                document.body.appendChild(toast);
            }
            
            toast.textContent = '✓ ' + message;
            toast.style.opacity = '0';
            toast.style.display = 'block';
            
            const rect = button.getBoundingClientRect();
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;
            
            const height = toast.offsetHeight || 28;
            const width = toast.offsetWidth || 120;
            toast.style.top = (rect.top + scrollTop - height - 8) + 'px';
            toast.style.left = (rect.left + scrollLeft + (rect.width / 2) - (width / 2)) + 'px';
            
            setTimeout(() => {
                toast.style.opacity = '1';
            }, 10);
            
            if (window.connectMWPToastTimer) {
                clearTimeout(window.connectMWPToastTimer);
            }
            
            window.connectMWPToastTimer = setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => {
                    if (toast.style.opacity === '0') {
                        toast.style.display = 'none';
                    }
                }, 200);
            }, 10000);
        }
        </script>
        <div class="wrap cmwp-wrap">

            <header class="cmwp-hero">
                <h1>🔌 connectMWP <span class="cmwp-ver">v<?php echo esc_html(self::version()); ?></span></h1>
                <p>Let an AI client publish to this WordPress site over a secure, direct connection &mdash; nothing routes through a third-party server.</p>
            </header>

            <div class="cmwp-switch">
                <div class="cmwp-switch-q">
                    <b>Connect an AI client</b>
                    <span>Pick the client you use &mdash; each one connects a little differently, and we&rsquo;ll show only the steps for yours.</span>
                </div>
                <div class="cmwp-ctabs" id="cmwp-client-tabs" role="tablist" aria-label="Choose your AI client">
                    <button type="button" class="cmwp-ctab active" data-client="device" role="tab" aria-selected="true">
                        <span class="cmwp-ctab-ic">🖥️</span>
                        <span><span class="cmwp-ctab-nm">Claude · Cursor · Cline</span><span class="cmwp-ctab-mh">Device pairing</span></span>
                    </button>
                    <button type="button" class="cmwp-ctab" data-client="chatgpt" role="tab" aria-selected="false">
                        <span class="cmwp-ctab-ic">💬</span>
                        <span><span class="cmwp-ctab-nm">ChatGPT</span><span class="cmwp-ctab-mh">OAuth sign-in</span></span>
                    </button>
                    <button type="button" class="cmwp-ctab" data-client="token" role="tab" aria-selected="false">
                        <span class="cmwp-ctab-ic">🔑</span>
                        <span><span class="cmwp-ctab-nm">Antigravity · Gemini CLI · other</span><span class="cmwp-ctab-mh">API token</span></span>
                    </button>
                </div>
            </div>

            <!-- DEVICE PAIRING panel (Claude / Cursor / Cline) -->
            <div class="cmwp-panel active" data-client-panel="device" role="tabpanel">

            <?php if ($page_state === 'mid-pair'):
                $npx_cmd = 'npx -y connectmwp-mcp add-site --enroll "' . $enrollment_string . '"';
                $stored  = get_option('connectmwp_enrollment_code');
                $remaining = is_array($stored) && isset($stored['expires']) ? intval($stored['expires']) - time() : 600;
                $remaining = max(0, $remaining);
                ?>
                <section class="cmwp-pairing-card">
                    <div class="cmwp-pc-head">
                        <h2>⚠️ Action Required — pair your local environment</h2>
                        <div class="cmwp-pc-badges">
                            <span class="cmwp-pc-badge timer">⏳ <span id="connectmwp-countdown">--:--</span></span>
                            <span class="cmwp-pc-badge type">One-Time Code</span>
                        </div>
                    </div>
                    <div class="cmwp-pc-instructions">
                        <strong>👉 How to Pair:</strong>
                        <ol>
                            <li>Open a Terminal window on your local computer (Node.js 18+ required).</li>
                            <li>Paste and run the command below — this page will auto-update on success.</li>
                        </ol>
                    </div>
                    <div class="cmwp-pc-cmd">
                        <textarea readonly class="cmwp-pc-textarea" id="cmwp-enroll-cmd"><?php echo esc_textarea($npx_cmd); ?></textarea>
                        <button type="button" class="cmwp-btn-copy" onclick="navigator.clipboard.writeText(document.getElementById('cmwp-enroll-cmd').value).then(() => showConnectMWPToast(this, 'Command copied!')).catch(() => showConnectMWPToast(this, 'Copy failed — select &amp; ⌘C'))">Copy</button>
                    </div>

                    <script>
                    (function() {
                        let secondsLeft = <?php echo intval($remaining); ?>;
                        const display = document.getElementById('connectmwp-countdown');
                        if (!display) return;
                        function updateTimer() {
                            if (secondsLeft <= 0) {
                                display.textContent = "Expired";
                                display.style.color = "#c0392b";
                                display.style.fontWeight = "700";
                                setTimeout(() => window.location.reload(), 1500);
                                return;
                            }
                            const m = Math.floor(secondsLeft / 60);
                            const s = secondsLeft % 60;
                            display.textContent = `${m}:${s < 10 ? '0' : ''}${s}`;
                            secondsLeft--;
                            setTimeout(updateTimer, 1000);
                        }
                        updateTimer();
                    })();
                    </script>

                    <script>
                    // Live pairing-completion poll (v2.0.16+): admin-ajax-backed, nonced,
                    // capability-gated. On a new key landing, flip the card to a success
                    // state and reload so the user sees the full new layout without manual
                    // refresh. Polls every 3s AND on visibilitychange (terminal handoff).
                    (function() {
                        const ajaxUrl = '<?php echo esc_js(admin_url('admin-ajax.php')); ?>';
                        const nonce = '<?php echo esc_js(wp_create_nonce('connectmwp_pairing_status')); ?>';
                        const initialTotal = <?php echo intval(count($all_keys_with_users)); ?>;
                        const initialLatest = <?php echo $most_recent ? "'" . esc_js($most_recent['key_id']) . "'" : 'null'; ?>;
                        let stopped = false;
                        let timer = null;
                        let failCount = 0; // consecutive poll failures (T062)

                        // After repeated poll failures (expired nonce, 5xx, network),
                        // stop the loop and TELL the admin instead of failing silent.
                        function noteFailureAndMaybeStop() {
                            failCount++;
                            if (failCount < 3) return;
                            stop();
                            const card = document.querySelector('.cmwp-pairing-card');
                            if (!card || document.getElementById('cmwp-poll-stalled')) return;
                            const note = document.createElement('p');
                            note.id = 'cmwp-poll-stalled';
                            note.style.cssText = 'margin: 12px 0 0; font-size: 12.5px; color: #b9770e;';
                            note.textContent = '⚠ Auto-refresh paused (could not reach the server). Reload this page after pairing to see the new client.';
                            card.appendChild(note);
                        }

                        // Named so the SAME reference can be detached in stop().
                        const onVisibility = function() {
                            if (document.visibilityState === 'visible' && !stopped) poll();
                        };

                        // Single teardown chokepoint (SSOT): flag, interval, listener.
                        function stop() {
                            stopped = true;
                            if (timer) clearInterval(timer);
                            document.removeEventListener('visibilitychange', onVisibility);
                        }

                        // DOM-only success state build — no innerHTML, so the server-supplied
                        // label is structurally XSS-safe.
                        function flipCardToSuccess(label) {
                            const card = document.querySelector('.cmwp-pairing-card');
                            if (!card) return;
                            card.style.transition = 'border-color 0.4s ease, box-shadow 0.4s ease';
                            card.style.borderLeftColor = '#16a085';
                            card.style.boxShadow = '0 10px 30px rgba(22, 160, 133, 0.20)';
                            while (card.firstChild) card.removeChild(card.firstChild);

                            const wrap = document.createElement('div');
                            wrap.style.cssText = 'text-align: center; padding: 30px;';

                            const emoji = document.createElement('div');
                            emoji.style.cssText = 'font-size: 48px; line-height: 1;';
                            emoji.textContent = '🎉';

                            const title = document.createElement('h3');
                            title.style.cssText = 'color: #16a085; margin: 14px 0 6px 0; font-size: 22px;';
                            title.textContent = 'Pairing successful!';

                            const msg = document.createElement('p');
                            msg.style.cssText = 'color: #34495e; font-size: 14px; margin: 0;';
                            msg.textContent = label
                                ? 'Connected: ' + label + ' — refreshing in a moment…'
                                : 'Refreshing in a moment…';

                            wrap.append(emoji, title, msg);
                            card.append(wrap);
                        }

                        async function poll() {
                            if (stopped) return;
                            try {
                                const params = new URLSearchParams({ action: 'connectmwp_pairing_status', _wpnonce: nonce });
                                const res = await fetch(ajaxUrl + '?' + params.toString(), { credentials: 'same-origin', cache: 'no-store' });
                                if (!res.ok) { noteFailureAndMaybeStop(); return; }
                                const data = await res.json();
                                failCount = 0; // a clean round resets the failure streak (T062)
                                const claimed = (data.total_keys > initialTotal) || (data.latest_key_id && data.latest_key_id !== initialLatest);
                                if (claimed) {
                                    stop();
                                    flipCardToSuccess(data.latest_label);
                                    setTimeout(function() { window.location.reload(); }, 1500);
                                    return;
                                }
                                if (!data.code_active) {
                                    stop();
                                }
                            } catch (e) { noteFailureAndMaybeStop(); }
                        }

                        poll();
                        timer = setInterval(poll, 3000);
                        document.addEventListener('visibilitychange', onVisibility);
                    })();
                    </script>
                </section>
            <?php endif; ?>

            <?php if ($show_what_now && $most_recent):
                $recent_user    = esc_html($most_recent['user_display'] ?? $most_recent['user_login']);
                $recent_login   = esc_html($most_recent['user_login']);
                $recent_roles   = !empty($most_recent['user_roles']) ? esc_html(implode(', ', $most_recent['user_roles'])) : 'no roles';
                $site_title_safe = esc_html(html_entity_decode(get_bloginfo('name'), ENT_QUOTES, 'UTF-8'));
                ?>
                <section class="cmwp-whatnow">
                    <h3>🎉 You just paired <?php echo esc_html($most_recent['label']); ?> — what now?</h3>
                    <ol>
                        <li>Your AI client can now read &amp; write <strong><?php echo $site_title_safe; ?></strong> as <strong><?php echo $recent_user; ?></strong> (<code><?php echo $recent_login; ?></code>, role: <?php echo $recent_roles; ?>).</li>
                        <li><strong>Test the connection:</strong> ask your AI <em>"list the tags on this site using connectMWP"</em>. The first time it uses each tool, your AI may ask for one-time permission — that's normal.</li>
                        <li><strong>If your AI doesn't see the connection</strong>, fully quit and relaunch the AI client (⌘Q on macOS, not just close the window).</li>
                        <li><strong>Want to use this site from another AI client on the same Mac?</strong> (Claude Desktop, Cursor, Antigravity, etc.) Register the same MCP server in each — <code>npx -y connectmwp-mcp</code>. They share this pairing; no new code needed.</li>
                    </ol>
                </section>
            <?php endif; ?>

            <?php if ($page_state === 'zero'): ?>
                <section class="cmwp-getstarted">
                    <div class="cmwp-step-tag">Step 1</div>
                    <h2>Pair your first AI client</h2>
                    <p>Generate a single-use pairing code, then run it in your terminal. Your local AI client will create an Ed25519 keypair and upload only its public key here. The private key never leaves your machine.</p>
                    <form method="post" action="" style="display: inline-block;">
                        <?php wp_nonce_field('connectmwp_generate_pairing'); ?>
                        <input type="hidden" name="connectmwp_action" value="generate_pairing" />
                        <button type="submit" class="cmwp-btn-primary-large">Generate Pairing Code</button>
                    </form>
                </section>
            <?php else: ?>
                <?php $client_count = count($all_keys_with_users); ?>
                <section class="cmwp-card">
                    <div class="cmwp-card-header">
                        <div>
                            <h2 class="cmwp-card-title">Your AI clients</h2>
                            <p class="cmwp-card-sub"><?php echo intval($client_count); ?> connected · all signing successfully</p>
                        </div>
                        <?php if ($page_state !== 'mid-pair'): ?>
                            <form method="post" action="" style="margin: 0;">
                                <?php wp_nonce_field('connectmwp_generate_pairing'); ?>
                                <input type="hidden" name="connectmwp_action" value="generate_pairing" />
                                <button type="submit" class="cmwp-btn-pair-another">+ Pair another</button>
                            </form>
                        <?php endif; ?>
                    </div>

                    <div class="cmwp-client-list">
                        <?php foreach ($all_keys_with_users as $k): ?>
                            <div class="cmwp-client-row">
                                <div class="cmwp-client-label">
                                    <span class="cmwp-client-dot<?php echo !empty($k['is_stale']) ? ' stale' : ''; ?>" aria-label="<?php echo !empty($k['is_stale']) ? 'stale' : 'connected'; ?>"></span>
                                    <?php echo esc_html($k['label']); ?>
                                    <?php if (!empty($k['is_just_paired'])): ?>
                                        <span class="cmwp-badge-new">JUST PAIRED</span>
                                    <?php endif; ?>
                                </div>
                                <div class="cmwp-client-action">
                                    <form method="post" style="margin: 0;">
                                        <?php wp_nonce_field('connectmwp_revoke_key'); ?>
                                        <input type="hidden" name="connectmwp_action" value="revoke_key" />
                                        <input type="hidden" name="key_id" value="<?php echo esc_attr($k['key_id']); ?>" />
                                        <button type="submit" class="cmwp-btn-revoke" onclick="return confirm('Revoke access for &quot;<?php echo esc_js($k['label']); ?>&quot;? This cannot be undone.');">Revoke access</button>
                                    </form>
                                </div>
                                <div class="cmwp-client-meta">
                                    <span class="cmwp-meta-times">paired <b><?php echo esc_html($k['display_created']); ?></b> as <b><?php echo esc_html($k['user_login']); ?></b><span class="cmwp-meta-sep">·</span>last used <b><?php echo esc_html($k['display_last_used']); ?></b></span>
                                    <span class="cmwp-meta-key"><code class="cmwp-copy" data-copy="<?php echo esc_attr($k['key_id']); ?>" title="Click to copy"><?php echo esc_html($k['key_id']); ?></code></span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <p class="cmwp-tz-note">Times shown in the site's configured timezone (Settings → General → Timezone). Click a key ID to copy it.</p>
                </section>
            <?php endif; ?>

            <section class="cmwp-config-card">
                <div class="cmwp-card-header">
                    <div>
                        <h2 class="cmwp-card-title">Add the MCP server to your app</h2>
                        <p class="cmwp-card-sub">After pairing, drop this registration into your AI app&rsquo;s settings. Every Claude / Cursor / Cline app on this Mac shares the pairing above &mdash; no extra setup per app.</p>
                    </div>
                </div>
<pre class="cmwp-config-json"><span class="cmwp-dim">{
  "mcpServers": {</span>
<span class="cmwp-hi">    "connectmwp": { "command": "npx", "args": ["-y", "connectmwp-mcp"] }</span>
<span class="cmwp-dim">  }
}</span></pre>
                <p class="cmwp-stdio-where"><b>Where to put it</b> &mdash; <b>Claude:</b> <code>claude_desktop_config.json</code> · <b>Cursor:</b> Settings → MCP · <b>Cline / Continue:</b> add an MCP server named <code>connectmwp</code>. Merge only the highlighted line into any existing <code>"mcpServers"</code> object, then fully quit &amp; relaunch the app (⌘Q on macOS).</p>
            </section>

            </div><!-- /device panel -->

            <!-- CHATGPT panel (OAuth) -->
            <div class="cmwp-panel" data-client-panel="chatgpt" role="tabpanel">
                <?php $this->render_chatgpt_oauth_info_card(); ?>
            </div>

            <!-- API TOKEN panel (Antigravity / Gemini CLI / other) -->
            <div class="cmwp-panel" data-client-panel="token" role="tabpanel">
                <?php $this->render_cgpt_card(); ?>
            </div>

            <script>
            // Click-to-copy on key_id chips (device-tab client list).
            (function() {
                document.querySelectorAll('.cmwp-copy').forEach(function(el) {
                    el.addEventListener('click', function() {
                        var text = el.dataset.copy || el.textContent;
                        // T056: never claim success if the clipboard write rejects.
                        navigator.clipboard.writeText(text).then(function() {
                            showConnectMWPToast(el, 'Key ID copied');
                        }).catch(function() {
                            showConnectMWPToast(el, 'Copy failed — select & ⌘C');
                        });
                    });
                });
            })();

            // Top-level client-family tab switching (device / chatgpt / token).
            (function() {
                var tabs = Array.prototype.slice.call(document.querySelectorAll('#cmwp-client-tabs .cmwp-ctab'));
                var panels = Array.prototype.slice.call(document.querySelectorAll('[data-client-panel]'));
                function activate(tab) {
                    var c = tab.dataset.client;
                    tabs.forEach(function(t) {
                        var on = (t === tab);
                        t.classList.toggle('active', on);
                        t.setAttribute('aria-selected', on ? 'true' : 'false');
                    });
                    panels.forEach(function(p) {
                        p.classList.toggle('active', p.dataset.clientPanel === c);
                    });
                }
                tabs.forEach(function(tab, i) {
                    tab.addEventListener('click', function() { activate(tab); });
                    // Arrow-key navigation (WAI-ARIA tabs pattern).
                    tab.addEventListener('keydown', function(e) {
                        var next = null;
                        if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
                        else if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
                        if (next) { e.preventDefault(); activate(next); next.focus(); }
                    });
                });
            })();
            </script>

            <?php
                // Merged "Your connections" — every connection type in ONE table
                // below the setup tabs (v2.3.0). Device keys + API tokens + OAuth
                // apps, each with the right revoke mechanism on its row.
                $token_rows = $this->get_cgpt_token_rows();
                $oauth_rows = $this->get_oauth_connection_rows();
                $total_conns = count($all_keys_with_users) + count($token_rows) + count($oauth_rows);
            ?>
            <section class="cmwp-card">
                <div class="cmwp-card-header">
                    <div>
                        <h2 class="cmwp-card-title">Your connections</h2>
                        <p class="cmwp-card-sub">Everything that can publish to this site, in one place. Revoke any row to cut it off.</p>
                    </div>
                </div>

                <div id="cmwp-conns-wrap" style="<?php echo $total_conns === 0 ? 'display:none;' : ''; ?>">
                    <table class="cmwp-conns" id="cmwp-conns-table">
                        <thead>
                            <tr><th>Type</th><th>Client / app</th><th>Bound user</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr>
                        </thead>
                        <tbody>
                            <?php foreach ($all_keys_with_users as $k): ?>
                                <tr>
                                    <td><span class="cmwp-ty cmwp-ty-key">🖥️ Device key</span></td>
                                    <td class="cmwp-conn-who"><?php echo esc_html($k['label']); ?><?php if (!empty($k['is_just_paired'])): ?> <span class="cmwp-badge-new">JUST PAIRED</span><?php endif; ?><span class="cmwp-conn-sub"><code class="cmwp-copy" data-copy="<?php echo esc_attr($k['key_id']); ?>" title="Click to copy"><?php echo esc_html($k['key_id']); ?></code></span></td>
                                    <td><?php echo esc_html($k['user_login']); ?></td>
                                    <td><?php echo esc_html($k['display_created']); ?></td>
                                    <td><?php echo esc_html($k['display_last_used']); ?></td>
                                    <td><span class="cmwp-stat<?php echo !empty($k['is_stale']) ? ' stale' : ''; ?>"><span class="cmwp-stat-dot"></span><?php echo !empty($k['is_stale']) ? 'Idle' : 'Connected'; ?></span></td>
                                    <td>
                                        <form method="post">
                                            <?php wp_nonce_field('connectmwp_revoke_key'); ?>
                                            <input type="hidden" name="connectmwp_action" value="revoke_key" />
                                            <input type="hidden" name="key_id" value="<?php echo esc_attr($k['key_id']); ?>" />
                                            <button type="submit" class="cmwp-btn-revoke" onclick="return confirm('Revoke access for &quot;<?php echo esc_js($k['label']); ?>&quot;? This cannot be undone.');">Revoke</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <?php foreach ($token_rows as $r): ?>
                                <tr data-token-row="<?php echo esc_attr($r['token_id']); ?>">
                                    <td><span class="cmwp-ty cmwp-ty-tok">🔑 API token</span></td>
                                    <td class="cmwp-conn-who"><?php echo esc_html($r['label'] !== '' ? $r['label'] : 'API token'); ?></td>
                                    <td><?php echo esc_html($r['user_display']); ?><?php echo $r['user_login'] !== '' ? ' <span style="color:#abb2b9;">(' . esc_html($r['user_login']) . ')</span>' : ''; ?></td>
                                    <td><?php echo esc_html($r['created'] !== '' ? $r['created'] : '—'); ?></td>
                                    <td><?php echo esc_html($r['last_used'] !== '' ? $r['last_used'] : 'never'); ?></td>
                                    <td><span class="cmwp-stat"><span class="cmwp-stat-dot"></span>Active</span></td>
                                    <td><button type="button" class="cmwp-btn-revoke cmwp-cgpt-revoke" data-token-id="<?php echo esc_attr($r['token_id']); ?>" data-label="<?php echo esc_attr($r['label'] !== '' ? $r['label'] : 'API token'); ?>">Revoke</button></td>
                                </tr>
                            <?php endforeach; ?>
                            <?php foreach ($oauth_rows as $r): $is_active = ($r['status'] === 'Active'); ?>
                                <tr data-family-row="<?php echo esc_attr($r['family']); ?>">
                                    <td><span class="cmwp-ty cmwp-ty-oauth">💬 ChatGPT OAuth</span></td>
                                    <td class="cmwp-conn-who"><?php echo esc_html($r['app']); ?></td>
                                    <td><?php echo esc_html($r['user_display']); ?><?php echo $r['user_login'] !== '' ? ' <span style="color:#abb2b9;">(' . esc_html($r['user_login']) . ')</span>' : ''; ?></td>
                                    <td><?php echo esc_html($r['created'] !== '' ? $r['created'] : '—'); ?></td>
                                    <td><?php echo esc_html($r['last_used'] !== '' ? $r['last_used'] : 'Never'); ?></td>
                                    <td><span class="cmwp-stat<?php echo $is_active ? '' : ' stale'; ?>"><span class="cmwp-stat-dot"></span><?php echo esc_html($r['status']); ?></span></td>
                                    <td><button type="button" class="cmwp-btn-revoke cmwp-oauth-revoke" data-family="<?php echo esc_attr($r['family']); ?>" data-app="<?php echo esc_attr($r['app']); ?>">Revoke</button></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <p class="cmwp-tz-note">Times shown in the site&rsquo;s configured timezone (Settings → General → Timezone). Click a device key ID to copy it. Tokens are never stored and can&rsquo;t be shown again &mdash; connections can only be revoked.</p>
                </div>
                <p id="cmwp-conns-empty" class="cmwp-tz-note" style="<?php echo $total_conns === 0 ? '' : 'display:none;'; ?>">No AI clients are connected yet. Use the tabs above to connect one.</p>
            </section>

            <script>
            // OAuth-connection revoke, delegated on the merged table. (API-token
            // revoke + generate live in the API-token card's own script, which also
            // targets this table. Device keys revoke via POST form -> page reload.)
            (function() {
                var ajaxUrl = '<?php echo esc_js(admin_url('admin-ajax.php')); ?>';
                var nonce = '<?php echo esc_js(wp_create_nonce('connectmwp_oauth_manage')); ?>';
                var tableBody = document.querySelector('#cmwp-conns-table tbody');
                var wrap = document.getElementById('cmwp-conns-wrap');
                var emptyMsg = document.getElementById('cmwp-conns-empty');
                if (!tableBody) return;
                tableBody.addEventListener('click', async function(e) {
                    var btn = e.target.closest('.cmwp-oauth-revoke');
                    if (!btn) return;
                    var family = btn.getAttribute('data-family');
                    var app = btn.getAttribute('data-app') || 'this app';
                    if (!window.confirm('Disconnect "' + app + '"? It will immediately lose access to this site. This cannot be undone.')) return;
                    btn.disabled = true;
                    btn.textContent = 'Revoking…';
                    try {
                        var body = new URLSearchParams({ action: 'connectmwp_oauth_revoke', _wpnonce: nonce, family: family });
                        var res = await fetch(ajaxUrl, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
                        var data = await res.json();
                        if (!res.ok || !data || !data.success) {
                            window.alert((data && data.data && data.data.message) ? data.data.message : 'Could not revoke connection.');
                            btn.disabled = false; btn.textContent = 'Revoke'; return;
                        }
                        var row = tableBody.querySelector('tr[data-family-row="' + (window.CSS && CSS.escape ? CSS.escape(family) : family) + '"]');
                        if (row) row.remove();
                        if (tableBody.querySelectorAll('tr').length === 0) {
                            if (wrap) wrap.style.display = 'none';
                            if (emptyMsg) emptyMsg.style.display = '';
                        }
                    } catch (err) {
                        window.alert('Could not revoke connection.');
                        btn.disabled = false; btn.textContent = 'Revoke';
                    }
                });
            })();
            </script>
        </div>
        <?php
    }

    /**
     * Gather API-token rows for the merged "Your connections" table. Single
     * source of this data (v2.3.0 — extracted from the old per-card token table).
     */
    private function get_cgpt_token_rows() {
        $tokens   = $this->list_cgpt_tokens();
        $user_ids = array_values(array_unique(array_filter(array_map(function ($t) {
            return intval($t['bound_user_id']);
        }, $tokens))));
        $user_map = [];
        if (!empty($user_ids)) {
            foreach (get_users(['include' => $user_ids]) as $u) {
                $user_map[intval($u->ID)] = $u;
            }
        }
        $rows = [];
        foreach ($tokens as $token_id => $t) {
            $u = $user_map[intval($t['bound_user_id'])] ?? null;
            $rows[] = [
                'token_id'     => $token_id,
                'label'        => $t['label'],
                'user_display' => $u ? ($u->display_name ?: $u->user_login) : 'Unknown user',
                'user_login'   => $u ? $u->user_login : '',
                'created'      => $this->format_cgpt_timestamp($t['created']),
                'last_used'    => $this->format_cgpt_timestamp($t['last_used']),
                'last_ip'      => $t['last_ip'],
            ];
        }
        usort($rows, function ($a, $b) {
            return strcmp($b['created'], $a['created']);
        });
        return $rows;
    }

    /**
     * Gather OAuth-connection rows (grouped by token family) for the merged
     * "Your connections" table. Single source of this data (v2.3.0 — extracted
     * from the old "Connected apps (OAuth)" card).
     */
    private function get_oauth_connection_rows() {
        $tokens = $this->list_oauth_tokens();

        $families = [];
        foreach ($tokens as $token_id => $t) {
            $family = (string) $t['family'];
            if ($family === '') {
                continue;
            }
            if (!isset($families[$family])) {
                $families[$family] = [
                    'family'           => $family,
                    'bound_user_id'    => intval($t['bound_user_id']),
                    'scope'            => (string) $t['scope'],
                    'client_id'        => (string) $t['client_id'],
                    'created'          => intval($t['created']),
                    'last_used'        => intval($t['last_used']),
                    'has_live_refresh' => false,
                ];
            }
            $grp =& $families[$family];
            $c = intval($t['created']);
            if ($c > 0 && ($grp['created'] === 0 || $c < $grp['created'])) {
                $grp['created'] = $c;
            }
            $lu = intval($t['last_used']);
            if ($lu > $grp['last_used']) {
                $grp['last_used'] = $lu;
            }
            if ($t['type'] === 'refresh' && intval($t['expires']) > 0 && time() < intval($t['expires'])) {
                $grp['has_live_refresh'] = true;
            }
            if ($grp['client_id'] === '' && (string) $t['client_id'] !== '') {
                $grp['client_id'] = (string) $t['client_id'];
            }
            if ($grp['scope'] === '' && (string) $t['scope'] !== '') {
                $grp['scope'] = (string) $t['scope'];
            }
            unset($grp);
        }

        $user_ids = array_values(array_unique(array_filter(array_map(function ($g) {
            return intval($g['bound_user_id']);
        }, $families))));
        $user_map = [];
        if (!empty($user_ids)) {
            foreach (get_users(['include' => $user_ids]) as $u) {
                $user_map[intval($u->ID)] = $u;
            }
        }

        $rows = [];
        foreach ($families as $g) {
            $u = $user_map[intval($g['bound_user_id'])] ?? null;
            $rows[] = [
                'family'       => $g['family'],
                'app'          => $this->oauth_app_display_name($g['client_id']),
                'user_display' => $u ? ($u->display_name ?: $u->user_login) : 'Unknown user',
                'user_login'   => $u ? $u->user_login : '',
                'scope'        => $g['scope'],
                'created'      => $this->format_oauth_timestamp($g['created']),
                'last_used'    => $this->format_oauth_timestamp($g['last_used']),
                'status'       => $g['has_live_refresh'] ? 'Active' : 'Expired',
            ];
        }
        usort($rows, function ($a, $b) {
            return strcmp($b['created'], $a['created']);
        });
        return $rows;
    }

    /**
     * "Connect ChatGPT (beta)" settings card (T5). Admin-only — render path is
     * already inside render_settings_page() which hard-gates on manage_options.
     * Lets an admin mint a ChatGPT bearer token bound to a chosen WP user, shows
     * the plaintext exactly once, lists existing tokens (metadata only — the
     * plaintext is never recoverable), and revokes per-row. All mutating calls go
     * through the nonce + manage_options-gated cgpt_generate/cgpt_revoke AJAX
     * actions. This card is admin UX only; it is NOT on the MCP traffic path.
     */
    private function render_cgpt_card() {
        // Eligible delegation targets: users who can edit posts. Default the
        // <select> to the current admin if they qualify. Batched query (no N+1).
        $eligible = get_users([
            'capability' => 'edit_posts',
            'orderby'    => 'display_name',
            'order'      => 'ASC',
            'number'     => 200,
        ]);
        $current_id = get_current_user_id();

        // Token count drives the generate cap; the token rows themselves now
        // render in the merged "Your connections" table (see get_cgpt_token_rows()).
        $at_cap = count($this->list_cgpt_tokens()) >= self::MAX_CGPT_TOKENS_PER_SITE;
        $path_token_enabled = $this->cgpt_path_token_enabled();
        ?>
        <section class="cmwp-card" id="cmwp-cgpt-card">
            <div class="cmwp-card-header">
                <div>
                    <h2 class="cmwp-card-title">API token &mdash; for Antigravity, Gemini CLI &amp; other MCP clients</h2>
                    <p class="cmwp-card-sub">Remote MCP clients that support a custom auth header (Antigravity, Gemini CLI, and similar) authenticate using a bearer token you generate here. Paste the token as an <code>Authorization: Bearer &lt;token&gt;</code> header in those clients alongside the connector URL shown after generation. The token never passes through any third-party server &mdash; it travels directly from the client to your site. Revoke it anytime from <strong>Your connections</strong> below.</p>
                    <p class="cmwp-card-sub" style="margin-top:8px;"><strong>Connecting ChatGPT instead?</strong> ChatGPT uses OAuth, not an API token &mdash; switch to the <strong>ChatGPT</strong> tab above.</p>
                </div>
            </div>

            <div class="cmwp-cgpt-gen">
                <label class="cmwp-cgpt-field">
                    <span class="cmwp-cgpt-flabel">Connect as</span>
                    <select id="cmwp-cgpt-user">
                        <?php foreach ($eligible as $u):
                            $display = $u->display_name ?: $u->user_login; ?>
                            <option value="<?php echo intval($u->ID); ?>" <?php selected($u->ID, $current_id); ?>>
                                <?php echo esc_html($display . ' (' . $u->user_login . ')'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label class="cmwp-cgpt-field">
                    <span class="cmwp-cgpt-flabel">Label (optional)</span>
                    <input type="text" id="cmwp-cgpt-label" placeholder="ChatGPT" maxlength="120" />
                </label>
                <button type="button" class="cmwp-btn-pair-another" id="cmwp-cgpt-generate" <?php echo $at_cap ? 'disabled' : ''; ?>>Generate token</button>
            </div>
            <?php if ($at_cap): ?>
                <p class="cmwp-tz-note" style="color:#c0392b;">You've reached the limit of <?php echo intval(self::MAX_CGPT_TOKENS_PER_SITE); ?> ChatGPT tokens. Revoke one below to generate a new one.</p>
            <?php endif; ?>

            <!-- One-time reveal panel (hidden until a token is minted) -->
            <div id="cmwp-cgpt-reveal" class="cmwp-cgpt-reveal" style="display:none;">
                <div class="cmwp-cgpt-warn">⚠️ <strong>Copy this token now — you won't be able to see it again.</strong> If you lose it, revoke it and generate a new one.</div>
                <div class="cmwp-pc-cmd">
                    <textarea readonly class="cmwp-pc-textarea" id="cmwp-cgpt-token"></textarea>
                    <button type="button" class="cmwp-btn-copy" id="cmwp-cgpt-copy-token">Copy</button>
                </div>

                <div class="cmwp-pc-instructions">
                    <strong>Add it to your MCP client (Antigravity, Gemini CLI, or similar):</strong>
                    <ol>
                        <li>In your client, add a new remote MCP server.</li>
                        <li>Set the <b>server URL</b> to the connector URL shown below.</li>
                        <li>Set the <b>authentication</b> to <b>Bearer token</b> (also labelled API key in some clients) and paste the token you just copied.</li>
                        <li>Save, then enable the connector.</li>
                    </ol>
                    <p style="margin:8px 0 4px;font-size:12.5px;color:#7f8c8d;">For multiple sites, add one entry per site and give each a distinct name (for example, <em>connectmwp-myblog</em>) so tools do not get mixed up between sites.</p>
                    <p style="margin:4px 0 0;font-size:12.5px;color:#c0392b;"><strong>Not for ChatGPT</strong> &mdash; ChatGPT uses OAuth, not an API token (see the ChatGPT tab).</p>
                </div>

                <p class="cmwp-cgpt-urllabel">Connector URL <span class="cmwp-cgpt-urltag">recommended</span></p>
                <div class="cmwp-pc-cmd">
                    <textarea readonly class="cmwp-pc-textarea cmwp-cgpt-url" id="cmwp-cgpt-url"></textarea>
                    <button type="button" class="cmwp-btn-copy" id="cmwp-cgpt-copy-url">Copy</button>
                </div>
                <!-- Path-token (URL-embedded) fallback URL — only revealed when the
                     admin has opted in via the toggle below. Hidden by default. -->
                <div id="cmwp-cgpt-url-path-block" style="<?php echo $path_token_enabled ? '' : 'display:none;'; ?>">
                    <p class="cmwp-cgpt-urllabel">If your host strips Authorization headers, use this URL instead <span class="cmwp-cgpt-urltag fallback">fallback</span></p>
                    <div class="cmwp-pc-cmd">
                        <textarea readonly class="cmwp-pc-textarea cmwp-cgpt-url" id="cmwp-cgpt-url-path"></textarea>
                        <button type="button" class="cmwp-btn-copy" id="cmwp-cgpt-copy-url-path">Copy</button>
                    </div>
                </div>
            </div>

            <!-- URL-embedded token fallback opt-in (OFF by default) -->
            <div class="cmwp-cgpt-pathtoggle">
                <label class="cmwp-cgpt-pathtoggle-row">
                    <input type="checkbox" id="cmwp-cgpt-path-toggle" <?php checked($path_token_enabled); ?> />
                    <span>Enable URL-embedded token fallback (only if your host strips Authorization headers)</span>
                </label>
                <p class="cmwp-cgpt-pathwarn">⚠ The URL-embedded form puts your token in the address, so it can appear in server/CDN/proxy access logs. Use it only if the normal (header) method fails, rotate the token periodically, and <strong>revoke it immediately if you suspect the URL was logged or shared</strong>.</p>
            </div>

            <p class="cmwp-tz-note" style="margin-top:14px;">Your active API tokens are listed in <strong>Your connections</strong> below, where you can revoke any of them.</p>
        </section>

        <style>
            .cmwp-cgpt-gen { display: flex; gap: 14px; align-items: flex-end; flex-wrap: wrap; margin-top: 4px; }
            .cmwp-cgpt-field { display: flex; flex-direction: column; gap: 4px; }
            .cmwp-cgpt-flabel { font-size: 12px; font-weight: 600; color: #7f8c8d; }
            .cmwp-cgpt-field select, .cmwp-cgpt-field input[type=text] { min-width: 220px; padding: 7px 10px; border: 1px solid #dbe5ed; border-radius: 6px; font-size: 13px; color: #2c3e50; background: #fff; }
            .cmwp-cgpt-reveal { margin-top: 16px; background: #fafbfc; border: 1px solid #eef2f4; border-left: 4px solid #16a085; border-radius: 8px; padding: 16px 18px; }
            .cmwp-cgpt-warn { font-size: 13px; color: #b9770e; background: #fef3e0; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; line-height: 1.5; }
            .cmwp-wrap textarea.cmwp-cgpt-url { height: 44px; font-size: 11.5px; }
            .cmwp-cgpt-urllabel { font-size: 12.5px; font-weight: 600; color: #34495e; margin: 12px 0 4px; }
            .cmwp-cgpt-urltag { font-size: 10px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #16a085; background: #d8f1ea; padding: 2px 7px; border-radius: 999px; }
            .cmwp-cgpt-urltag.fallback { color: #7f8c8d; background: #ecf0f1; }
            .cmwp-cgpt-pathtoggle { margin-top: 16px; padding: 12px 14px; background: #fdf6ec; border: 1px solid #f3e2c7; border-radius: 8px; }
            .cmwp-cgpt-pathtoggle-row { display: flex; align-items: flex-start; gap: 8px; font-size: 13px; font-weight: 600; color: #34495e; cursor: pointer; }
            .cmwp-cgpt-pathtoggle-row input[type=checkbox] { margin-top: 2px; }
            .cmwp-cgpt-pathwarn { margin: 8px 0 0; font-size: 12.5px; line-height: 1.5; color: #b9770e; }
        </style>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const ajaxUrl = '<?php echo esc_js(admin_url('admin-ajax.php')); ?>';
            const nonce = '<?php echo esc_js(wp_create_nonce('connectmwp_cgpt')); ?>';
            const maxTokens = <?php echo intval(self::MAX_CGPT_TOKENS_PER_SITE); ?>;

            const genBtn   = document.getElementById('cmwp-cgpt-generate');
            const userSel  = document.getElementById('cmwp-cgpt-user');
            const labelInp = document.getElementById('cmwp-cgpt-label');
            const reveal   = document.getElementById('cmwp-cgpt-reveal');
            const tokenTa  = document.getElementById('cmwp-cgpt-token');
            const urlTa    = document.getElementById('cmwp-cgpt-url');
            const urlPathTa= document.getElementById('cmwp-cgpt-url-path');
            const urlPathBlock = document.getElementById('cmwp-cgpt-url-path-block');
            const pathToggle = document.getElementById('cmwp-cgpt-path-toggle');
            // Token rows render in the shared "Your connections" table below.
            const tableWrap= document.getElementById('cmwp-conns-wrap');
            const tableBody= document.querySelector('#cmwp-conns-table tbody');
            const emptyMsg = document.getElementById('cmwp-conns-empty');

            function wireCopy(btnId, srcEl) {
                const btn = document.getElementById(btnId);
                if (!btn) return;
                btn.addEventListener('click', function() {
                    navigator.clipboard.writeText(srcEl.value)
                        .then(function() { showConnectMWPToast(btn, 'Copied'); })
                        .catch(function() { showConnectMWPToast(btn, 'Copy failed — select & ⌘C'); });
                });
            }
            wireCopy('cmwp-cgpt-copy-token', tokenTa);
            wireCopy('cmwp-cgpt-copy-url', urlTa);
            wireCopy('cmwp-cgpt-copy-url-path', urlPathTa);

            if (genBtn) {
                genBtn.addEventListener('click', async function() {
                    genBtn.disabled = true;
                    const original = genBtn.textContent;
                    genBtn.textContent = 'Generating…';
                    try {
                        const body = new URLSearchParams({
                            action: 'connectmwp_cgpt_generate',
                            _wpnonce: nonce,
                            bound_user_id: userSel ? userSel.value : '',
                            label: labelInp ? labelInp.value : ''
                        });
                        const res = await fetch(ajaxUrl, {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: body.toString()
                        });
                        const data = await res.json();
                        if (!res.ok || !data || !data.success) {
                            const msg = (data && data.data && data.data.message) ? data.data.message : 'Could not generate token, please try again.';
                            window.alert(msg);
                            genBtn.disabled = false;
                            genBtn.textContent = original;
                            return;
                        }
                        const d = data.data;
                        tokenTa.value   = d.token;
                        urlTa.value     = d.connector_url;
                        // The path-token URL is only present when the fallback is
                        // enabled; otherwise leave the (hidden) field blank.
                        if (urlPathTa) urlPathTa.value = d.connector_url_path || '';
                        reveal.style.display = 'block';
                        reveal.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                        // Insert the new token row at the top of the table (DOM-built,
                        // no innerHTML, so server-supplied strings are XSS-safe).
                        addRow({
                            token_id: d.token_id,
                            label: d.label || 'ChatGPT',
                            user_display: d.user_display,
                            user_login: d.user_login,
                            created: d.created || '—',
                            last_used: 'never',
                            last_ip: '—'
                        });
                        genBtn.textContent = original;
                        labelInp && (labelInp.value = '');
                        refreshCapState();
                    } catch (e) {
                        window.alert('Could not generate token, please try again.');
                        genBtn.disabled = false;
                        genBtn.textContent = original;
                    }
                });
            }

            // URL-embedded fallback opt-in toggle. Persists the boolean via the
            // manage_options + nonce-gated ajax action, then reveals/hides the
            // path-token URL block. On failure, revert the checkbox to its prior
            // state so the UI never claims a setting that didn't persist.
            if (pathToggle) {
                pathToggle.addEventListener('change', async function() {
                    const desired = pathToggle.checked;
                    pathToggle.disabled = true;
                    try {
                        const body = new URLSearchParams({
                            action: 'connectmwp_cgpt_set_path_token',
                            _wpnonce: nonce,
                            enabled: desired ? '1' : '0'
                        });
                        const res = await fetch(ajaxUrl, {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: body.toString()
                        });
                        const data = await res.json();
                        if (!res.ok || !data || !data.success) {
                            const msg = (data && data.data && data.data.message) ? data.data.message : 'Could not update this setting.';
                            window.alert(msg);
                            pathToggle.checked = !desired;
                        } else {
                            const on = !!(data.data && data.data.enabled);
                            pathToggle.checked = on;
                            if (urlPathBlock) urlPathBlock.style.display = on ? '' : 'none';
                        }
                    } catch (e) {
                        window.alert('Could not update this setting.');
                        pathToggle.checked = !desired;
                    } finally {
                        pathToggle.disabled = false;
                    }
                });
            }

            function cell(text, mutedSuffix) {
                const td = document.createElement('td');
                td.appendChild(document.createTextNode(text == null ? '' : String(text)));
                if (mutedSuffix) {
                    const span = document.createElement('span');
                    span.style.color = '#abb2b9';
                    span.appendChild(document.createTextNode(' (' + mutedSuffix + ')'));
                    td.appendChild(span);
                }
                return td;
            }

            // Build a row in the MERGED-table format (Type pill + who + meta +
            // status + revoke), matching the server-rendered token rows.
            function addRow(r) {
                if (!tableBody) return;
                const label = r.label || 'API token';
                const tr = document.createElement('tr');
                tr.setAttribute('data-token-row', r.token_id);

                const tyTd = document.createElement('td');
                const ty = document.createElement('span');
                ty.className = 'cmwp-ty cmwp-ty-tok';
                ty.textContent = '🔑 API token';
                tyTd.appendChild(ty);
                tr.appendChild(tyTd);

                const whoTd = document.createElement('td');
                whoTd.className = 'cmwp-conn-who';
                whoTd.appendChild(document.createTextNode(label));
                tr.appendChild(whoTd);

                tr.appendChild(cell(r.user_display, r.user_login || null));
                tr.appendChild(cell(r.created));
                tr.appendChild(cell(r.last_used));

                const stTd = document.createElement('td');
                const st = document.createElement('span');
                st.className = 'cmwp-stat';
                const dot = document.createElement('span');
                dot.className = 'cmwp-stat-dot';
                st.appendChild(dot);
                st.appendChild(document.createTextNode('Active'));
                stTd.appendChild(st);
                tr.appendChild(stTd);

                const actionTd = document.createElement('td');
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'cmwp-btn-revoke cmwp-cgpt-revoke';
                btn.setAttribute('data-token-id', r.token_id);
                btn.setAttribute('data-label', label);
                btn.textContent = 'Revoke';
                actionTd.appendChild(btn);
                tr.appendChild(actionTd);

                tableBody.insertBefore(tr, tableBody.firstChild);
                if (tableWrap) tableWrap.style.display = '';
                if (emptyMsg) emptyMsg.style.display = 'none';
            }

            function refreshCapState() {
                const count = tableBody ? tableBody.querySelectorAll('tr[data-token-row]').length : 0;
                if (genBtn) genBtn.disabled = count >= maxTokens;
            }

            // Delegated revoke handler (covers both server-rendered and JS-added rows).
            if (tableBody) {
                tableBody.addEventListener('click', async function(e) {
                    const btn = e.target.closest('.cmwp-cgpt-revoke');
                    if (!btn) return;
                    const tokenId = btn.getAttribute('data-token-id');
                    const label = btn.getAttribute('data-label') || 'this token';
                    if (!window.confirm('Revoke "' + label + '"? That client will immediately lose access. This cannot be undone.')) return;
                    btn.disabled = true;
                    btn.textContent = 'Revoking…';
                    try {
                        const body = new URLSearchParams({
                            action: 'connectmwp_cgpt_revoke',
                            _wpnonce: nonce,
                            token_id: tokenId
                        });
                        const res = await fetch(ajaxUrl, {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: body.toString()
                        });
                        const data = await res.json();
                        if (!res.ok || !data || !data.success) {
                            const msg = (data && data.data && data.data.message) ? data.data.message : 'Could not revoke token.';
                            window.alert(msg);
                            btn.disabled = false;
                            btn.textContent = 'Revoke';
                            return;
                        }
                        const row = tableBody.querySelector('tr[data-token-row="' + (window.CSS && CSS.escape ? CSS.escape(tokenId) : tokenId) + '"]');
                        if (row) row.remove();
                        if (tableBody.querySelectorAll('tr').length === 0) {
                            if (tableWrap) tableWrap.style.display = 'none';
                            if (emptyMsg) emptyMsg.style.display = '';
                        }
                        refreshCapState();
                    } catch (err) {
                        window.alert('Could not revoke token.');
                        btn.disabled = false;
                        btn.textContent = 'Revoke';
                    }
                });
            }
        });
        </script>
        <?php
    }

    /**
     * "ChatGPT (OAuth)" static info card. Admin-only — render path is already
     * inside render_settings_page() which hard-gates on manage_options. Explains
     * the OAuth connection flow for ChatGPT: paste the /mcp URL into ChatGPT,
     * choose OAuth, sign in as an admin, approve. No token is generated here —
     * ChatGPT's OAuth flow handles authentication automatically. Purely static
     * markup; no AJAX or backend logic touched.
     */
    private function render_chatgpt_oauth_info_card() {
        $mcp_url = esc_url(rest_url(self::API_NAMESPACE . '/mcp'));
        ?>
        <section class="cmwp-card" id="cmwp-chatgpt-oauth-info">
            <div class="cmwp-card-header">
                <div>
                    <h2 class="cmwp-card-title">ChatGPT (OAuth)</h2>
                    <p class="cmwp-card-sub">ChatGPT connects via OAuth &mdash; no token is generated or pasted. ChatGPT&rsquo;s connector UI offers only OAuth, No-Auth, and Mixed authentication modes, so it uses the plugin&rsquo;s built-in OAuth 2.1 sign-in instead of an API token.</p>
                </div>
            </div>

            <div class="cmwp-pc-instructions" style="margin-top:0;">
                <strong>How to connect ChatGPT to this site:</strong>
                <ol>
                    <li>In ChatGPT, open <strong>Settings &rarr; Apps (Connectors)</strong>, enable Developer mode, then create a new connector.</li>
                    <li>Set the connector URL to the address shown below and choose <strong>Authentication: OAuth</strong>.</li>
                    <li>Click <strong>Sign in</strong>. You will be redirected to this site&rsquo;s login screen &mdash; sign in as an <strong>administrator</strong>.</li>
                    <li>On the consent screen, review the requested access and click <strong>Approve</strong>.</li>
                    <li>ChatGPT completes the connection. The new session appears in the <strong>Connected apps (OAuth)</strong> card below. To disconnect at any time, click Revoke there.</li>
                </ol>
                <p style="margin:10px 0 4px;font-size:12.5px;color:#7f8c8d;">For multiple sites, add one connector per site and give each a clear name (for example, <em>connectmwp-myblog</em>) so tools do not get mixed up between sites.</p>
            </div>

            <p class="cmwp-cgpt-urllabel" style="margin-top:14px;">Connector URL</p>
            <div class="cmwp-pc-cmd">
                <textarea readonly class="cmwp-pc-textarea cmwp-cgpt-url" id="cmwp-oauth-mcp-url"><?php echo esc_textarea($mcp_url); ?></textarea>
                <button type="button" class="cmwp-btn-copy" id="cmwp-oauth-copy-url">Copy</button>
            </div>

            <script>
            (function() {
                const btn = document.getElementById('cmwp-oauth-copy-url');
                const ta  = document.getElementById('cmwp-oauth-mcp-url');
                if (btn && ta) {
                    btn.addEventListener('click', function() {
                        navigator.clipboard.writeText(ta.value)
                            .then(function() { showConnectMWPToast(btn, 'Copied'); })
                            .catch(function() { showConnectMWPToast(btn, 'Copy failed — select & ⌘C'); });
                    });
                }
            })();
            </script>
        </section>
        <?php
    }

    /**
     * Derive a human-readable app name from a stored OAuth client_id. The
     * client_id is typically a URL (dynamic-registration redirect/issuer), so we
     * surface its host (e.g. "chatgpt.com"). No client_name is stored today, so
     * the host is the honest, available identifier. Falls back to the raw
     * client_id when the host can't be parsed, and to "Unknown app" when empty.
     */
    private function oauth_app_display_name($client_id) {
        $client_id = (string) $client_id;
        if ($client_id === '') {
            return 'Unknown app';
        }
        $host = wp_parse_url($client_id, PHP_URL_HOST);
        if (is_string($host) && $host !== '') {
            return $host;
        }
        return $client_id;
    }
}

// Instantiate
ConnectMWP_Agent::instance();

