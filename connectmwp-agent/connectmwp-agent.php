<?php
/**
 * Plugin Name: connectMWP
 * Plugin URI: https://connectmwp.com
 * Description: Securely let your own local AI client (Claude, Cursor) publish to this WordPress site over a signed, session-less Ed25519 connection — no login, no central server.
 * Version: 2.1.0
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

    // ChatGPT bearer-token verifier IP throttle (T3). Mirrors the enroll
    // limiter (cmwp_enroll_limit_*): only FAILED resolves count toward the
    // limit, so a legitimate client making many authenticated calls is never
    // penalized. Once CGPT_AUTH_MAX_FAILURES failed attempts accumulate from
    // one IP within CGPT_AUTH_LOCKOUT_SECONDS, further attempts from that IP
    // are rejected until the transient expires. The key hashes the IP so no
    // raw PII lands in the option name.
    const CGPT_AUTH_MAX_FAILURES   = 10;   // failed-resolve attempts per IP before lockout
    const CGPT_AUTH_LOCKOUT_SECONDS = 600; // lockout / failure-count window (10 min)

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

        // 1. Enforce HTTPS
        if (!is_ssl()) {
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

        // VR-5: Enforce HTTPS first.
        if (!is_ssl()) {
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
            return new WP_Error(
                $code,
                $this->describe_verification_error($code),
                array('status' => $this->cgpt_status_for_code($code))
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
        if ($token === '' && $request instanceof WP_REST_Request) {
            $route_token = $request->get_param('token');
            if (is_string($route_token)) {
                $token = trim($route_token);
            }
        }

        if ($token === '') {
            $this->verification_error_code = 'connectmwp_cgpt_missing_token';
            $this->cgpt_token_verified = false;
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
                return 401;
            case 'connectmwp_cgpt_rate_limited':
                return 429;
            case 'connectmwp_cgpt_insecure_transport':
            case 'connectmwp_cgpt_unbound_token':
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

        // NOTE: the plaintext is returned exactly once, here, to the admin's own
        // browser. It is intentionally NOT logged anywhere.
        wp_send_json_success([
            'token'         => $result['plaintext'],
            'token_id'      => $result['token_id'],
            'label'         => $label,
            'bound_user_id' => $bound_user_id,
            'user_display'  => $target->display_name ?: $target->user_login,
            'user_login'    => $target->user_login,
            'created'       => $this->format_cgpt_timestamp($result['record']['created'] ?? ''),
            'connector_url' => $urls['header'],
            'connector_url_path' => $urls['path'],
        ]);
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
     * Handle Public Key Enrollment
     */
    public function enroll_client_handler(WP_REST_Request $request) {
        // Enforce SSL unless it is localhost
        $client_ip = $this->get_client_ip();
        $is_localhost = in_array($client_ip, ['127.0.0.1', '::1', 'localhost'], true) || (isset($_SERVER['HTTP_HOST']) && preg_match('/localhost|\.local|\.test/i', $_SERVER['HTTP_HOST']));
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
                <p>Secure, signature-based direct connector between local AI clients (Claude Desktop, Cursor, Antigravity, etc.) and this WordPress site.</p>
            </header>

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
                        <h2 class="cmwp-card-title">Configure an AI client</h2>
                        <p class="cmwp-card-sub">Drop this MCP server registration into your AI app's settings. The pairing above gives every AI client on this Mac the same access.</p>
                        <p class="cmwp-card-sub"><?php echo esc_html__('Using ChatGPT? It connects differently — see the "Connect ChatGPT (beta)" section below.', 'connectmwp'); ?></p>
                    </div>
                </div>

                <div class="cmwp-tabs" id="cmwp-config-tabs" role="tablist" aria-label="AI client configuration">
                    <button type="button" class="cmwp-tab active" data-target="claude" role="tab" aria-selected="true">Claude Desktop</button>
                    <button type="button" class="cmwp-tab" data-target="cursor" role="tab" aria-selected="false">Cursor</button>
                    <button type="button" class="cmwp-tab" data-target="other" role="tab" aria-selected="false">Other (Cline, Continue, …)</button>
                </div>

                <div class="cmwp-tab-tip" data-tip="claude">
                    Edit <code>claude_desktop_config.json</code>. If you already have other MCP servers, merge only the <b>highlighted block</b> into your existing <code>"mcpServers"</code> object.
                </div>
<pre class="cmwp-config-json" data-pane="claude"><span class="cmwp-dim">{
  "mcpServers": {</span>
<span class="cmwp-hi">    "connectmwp": {
      "command": "npx",
      "args": ["-y", "connectmwp-mcp"]
    }</span>
<span class="cmwp-dim">  }
}</span></pre>

                <div class="cmwp-tab-tip" data-tip="cursor" style="display:none">
                    Cursor: Settings → Features → MCP. Merge only the <b>highlighted block</b> into your existing <code>"mcpServers"</code> object.
                </div>
<pre class="cmwp-config-json" data-pane="cursor" style="display:none"><span class="cmwp-dim">{
  "mcpServers": {</span>
<span class="cmwp-hi">    "connectmwp": {
      "command": "npx",
      "args": ["-y", "connectmwp-mcp"]
    }</span>
<span class="cmwp-dim">  }
}</span></pre>

                <div class="cmwp-tab-tip" data-tip="other" style="display:none">
                    For Cline, Continue, or any other MCP-capable client: register a stdio MCP server named <code>connectmwp</code> with command <code>npx</code> and args <code>["-y", "connectmwp-mcp"]</code>. Exact menu paths vary by app.
                </div>
<pre class="cmwp-config-json" data-pane="other" style="display:none"><span class="cmwp-dim">Command:</span>  npx
<span class="cmwp-dim">Args:</span>     -y connectmwp-mcp
<span class="cmwp-dim">Name:</span>     connectmwp
<span class="cmwp-dim">Transport:</span> stdio</pre>
            </section>

            <script>
            // Click-to-copy on key_id chips + tab switching for the Configure card.
            (function() {
                document.querySelectorAll('.cmwp-copy').forEach(function(el) {
                    el.addEventListener('click', function() {
                        const text = el.dataset.copy || el.textContent;
                        // T056: never claim success if the clipboard write rejects
                        // (non-secure context, unfocused doc, restrictive policy).
                        navigator.clipboard.writeText(text).then(function() {
                            showConnectMWPToast(el, 'Key ID copied');
                        }).catch(function() {
                            showConnectMWPToast(el, 'Copy failed — select & ⌘C');
                        });
                    });
                });

                const tabs = Array.prototype.slice.call(document.querySelectorAll('#cmwp-config-tabs .cmwp-tab'));
                function activateTab(tab) {
                    const target = tab.dataset.target;
                    tabs.forEach(function(t) {
                        const on = t === tab;
                        t.classList.toggle('active', on);
                        t.setAttribute('aria-selected', on ? 'true' : 'false');
                    });
                    document.querySelectorAll('[data-pane]').forEach(function(p) {
                        p.style.display = (p.dataset.pane === target ? 'block' : 'none');
                    });
                    document.querySelectorAll('[data-tip]').forEach(function(p) {
                        p.style.display = (p.dataset.tip === target ? 'block' : 'none');
                    });
                }
                tabs.forEach(function(tab, i) {
                    tab.addEventListener('click', function() { activateTab(tab); });
                    // Arrow-key navigation between tabs (WAI-ARIA tabs pattern).
                    tab.addEventListener('keydown', function(e) {
                        let next = null;
                        if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
                        else if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
                        if (next) { e.preventDefault(); activateTab(next); next.focus(); }
                    });
                });
            })();
            </script>

            <?php $this->render_cgpt_card(); ?>
        </div>
        <?php
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

        // Existing tokens, newest first, with bound-user display resolved via one
        // batched get_users() (mirrors the key-table N+1 fix above).
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
        // Newest first by created string (mysql datetime sorts lexicographically).
        usort($rows, function ($a, $b) {
            return strcmp($b['created'], $a['created']);
        });

        $at_cap = count($tokens) >= self::MAX_CGPT_TOKENS_PER_SITE;
        ?>
        <section class="cmwp-card" id="cmwp-cgpt-card">
            <div class="cmwp-card-header">
                <div>
                    <h2 class="cmwp-card-title">🤖 Connect ChatGPT <span class="cmwp-badge-new">BETA</span></h2>
                    <p class="cmwp-card-sub">ChatGPT connects directly to <strong>this site</strong> using a token you generate here. The token lives inside your ChatGPT connector settings — it never passes through any third-party server. Revoke it anytime below.</p>
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
                    <strong>👉 Add it to ChatGPT:</strong>
                    <ol>
                        <li>In ChatGPT, open <b>Settings → Apps → Advanced → Developer mode</b>, then <b>Create app</b> (a custom connector).</li>
                        <li>Paste the <b>connector URL</b> below.</li>
                        <li>For authentication choose <b>API key</b> and paste the token you just copied.</li>
                        <li>Save, then enable the connector in a new chat.</li>
                    </ol>
                    <p style="margin:8px 0 4px;font-size:12.5px;color:#7f8c8d;">ChatGPT moves these menus around — if the labels differ, look for "developer mode" / "create connector" / "API key auth".</p>
                </div>

                <p class="cmwp-cgpt-urllabel">Connector URL <span class="cmwp-cgpt-urltag">recommended</span></p>
                <div class="cmwp-pc-cmd">
                    <textarea readonly class="cmwp-pc-textarea cmwp-cgpt-url" id="cmwp-cgpt-url"></textarea>
                    <button type="button" class="cmwp-btn-copy" id="cmwp-cgpt-copy-url">Copy</button>
                </div>
                <p class="cmwp-cgpt-urllabel">If your host strips Authorization headers, use this URL instead <span class="cmwp-cgpt-urltag fallback">fallback</span></p>
                <div class="cmwp-pc-cmd">
                    <textarea readonly class="cmwp-pc-textarea cmwp-cgpt-url" id="cmwp-cgpt-url-path"></textarea>
                    <button type="button" class="cmwp-btn-copy" id="cmwp-cgpt-copy-url-path">Copy</button>
                </div>
            </div>

            <!-- Existing tokens table -->
            <div id="cmwp-cgpt-table-wrap" style="<?php echo empty($rows) ? 'display:none;' : ''; ?>margin-top:18px;">
                <h3 class="cmwp-card-title" style="font-size:14px;margin-bottom:8px;">Existing ChatGPT tokens</h3>
                <table class="cmwp-cgpt-table" id="cmwp-cgpt-table">
                    <thead>
                        <tr>
                            <th>Label</th><th>Bound user</th><th>Created</th><th>Last used</th><th>Last IP</th><th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($rows as $r): ?>
                            <tr data-token-row="<?php echo esc_attr($r['token_id']); ?>">
                                <td><?php echo esc_html($r['label'] !== '' ? $r['label'] : 'ChatGPT'); ?></td>
                                <td><?php echo esc_html($r['user_display']); ?><?php echo $r['user_login'] !== '' ? ' <span style="color:#abb2b9;">(' . esc_html($r['user_login']) . ')</span>' : ''; ?></td>
                                <td><?php echo esc_html($r['created'] !== '' ? $r['created'] : '—'); ?></td>
                                <td><?php echo esc_html($r['last_used'] !== '' ? $r['last_used'] : 'never'); ?></td>
                                <td><?php echo esc_html($r['last_ip'] !== '' ? $r['last_ip'] : '—'); ?></td>
                                <td><button type="button" class="cmwp-btn-revoke cmwp-cgpt-revoke" data-token-id="<?php echo esc_attr($r['token_id']); ?>" data-label="<?php echo esc_attr($r['label'] !== '' ? $r['label'] : 'ChatGPT'); ?>">Revoke</button></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <p class="cmwp-tz-note">Times shown in the site's configured timezone. The token value itself is never stored and cannot be shown again — only revoked.</p>
            </div>
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
            .cmwp-cgpt-table { width: 100%; border-collapse: collapse; font-size: 13px; }
            .cmwp-cgpt-table th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; color: #7f8c8d; padding: 6px 10px; border-bottom: 1px solid #eef2f4; }
            .cmwp-cgpt-table td { padding: 9px 10px; border-bottom: 1px solid #f4f7f9; color: #34495e; vertical-align: middle; }
        </style>

        <script>
        (function() {
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
            const tableWrap= document.getElementById('cmwp-cgpt-table-wrap');
            const tableBody= document.querySelector('#cmwp-cgpt-table tbody');

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
                        urlPathTa.value = d.connector_url_path;
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

            function addRow(r) {
                if (!tableBody) return;
                const tr = document.createElement('tr');
                tr.setAttribute('data-token-row', r.token_id);
                tr.appendChild(cell(r.label));
                tr.appendChild(cell(r.user_display, r.user_login || null));
                tr.appendChild(cell(r.created));
                tr.appendChild(cell(r.last_used));
                tr.appendChild(cell(r.last_ip));
                const actionTd = document.createElement('td');
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'cmwp-btn-revoke cmwp-cgpt-revoke';
                btn.setAttribute('data-token-id', r.token_id);
                btn.setAttribute('data-label', r.label);
                btn.textContent = 'Revoke';
                actionTd.appendChild(btn);
                tr.appendChild(actionTd);
                tableBody.insertBefore(tr, tableBody.firstChild);
                if (tableWrap) tableWrap.style.display = '';
            }

            function refreshCapState() {
                const count = tableBody ? tableBody.querySelectorAll('tr').length : 0;
                if (genBtn) genBtn.disabled = count >= maxTokens;
            }

            // Delegated revoke handler (covers both server-rendered and JS-added rows).
            if (tableBody) {
                tableBody.addEventListener('click', async function(e) {
                    const btn = e.target.closest('.cmwp-cgpt-revoke');
                    if (!btn) return;
                    const tokenId = btn.getAttribute('data-token-id');
                    const label = btn.getAttribute('data-label') || 'this token';
                    if (!window.confirm('Revoke "' + label + '"? ChatGPT will immediately lose access. This cannot be undone.')) return;
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
                        if (tableWrap && tableBody.querySelectorAll('tr').length === 0) tableWrap.style.display = 'none';
                        refreshCapState();
                    } catch (err) {
                        window.alert('Could not revoke token.');
                        btn.disabled = false;
                        btn.textContent = 'Revoke';
                    }
                });
            }
        })();
        </script>
        <?php
    }
}

// Instantiate
ConnectMWP_Agent::instance();

