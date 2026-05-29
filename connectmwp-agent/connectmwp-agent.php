<?php
/**
 * Plugin Name: connectMWP Agent
 * Plugin URI: https://connectmwp.com
 * Description: Secure remote connector for connectmwp.com. Exposes safe REST API and Admin-AJAX endpoints signed with client-level tokens.
 * Version: 2.0.24
 * Author: Stefan Heinz, 2morrow.ai
 * Author URI: https://2morrow.ai
 * License: GPLv2
 */

defined('ABSPATH') || exit;

class ConnectMWP_Agent {

    const VERSION = '2.0.24';
    const OPTION_TOKENS = 'connectmwp_agent_tokens';
    const OPTION_NONCES = 'connectmwp_agent_nonces';
    const API_NAMESPACE = 'connectmwp/v1';

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

        // Admin settings page hook
        add_action('admin_menu', [$this, 'add_settings_page']);
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
        if (abs(time() - intval($timestamp)) > 300) {
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

    private function is_replay_signature($sig_hash) {
        $option_name = 'cmwp_sig_' . $sig_hash;
        $now = time();
        $expiry = $now + 360;

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

    private function find_key_by_id($key_id) {
        $keys = get_option('connectmwp_keys', []);
        if (is_array($keys) && isset($keys[$key_id])) {
            return $keys[$key_id];
        }
        return false;
    }

    private function update_key_last_used($user_id, $key_id) {
        $keys = get_option('connectmwp_keys', []);
        if (is_array($keys) && isset($keys[$key_id])) {
            $last_used_str = $keys[$key_id]['last_used'] ?? '';
            $last_used_time = !empty($last_used_str) && $last_used_str !== 'Never' ? strtotime($last_used_str) : 0;
            if (time() - $last_used_time > 60) {
                $keys[$key_id]['last_used'] = current_time('mysql');
                $keys[$key_id]['last_ip'] = $this->get_client_ip();
                update_option('connectmwp_keys', $keys, 'no');
            }
        }
    }

    private function get_client_ip() {
        if (!empty($_SERVER['REMOTE_ADDR']) && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
            return $_SERVER['REMOTE_ADDR'];
        }
        return 'unknown';
    }

    // Permission callbacks
    public function check_read_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return user_can($this->bound_user_id, 'edit_posts');
    }

    public function check_edit_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return user_can($this->bound_user_id, 'edit_posts');
    }

    public function check_edit_post_permission($request) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        $post_id = intval($request['id']);
        return user_can($this->bound_user_id, 'edit_post', $post_id);
    }

    public function check_delete_post_permission($request) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        $post_id = intval($request['id']);
        return user_can($this->bound_user_id, 'delete_post', $post_id);
    }

    public function check_upload_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return user_can($this->bound_user_id, 'upload_files');
    }

    public function check_taxonomy_permission($request = null) {
        if (!$this->verify_request_signature($request)) {
            return false;
        }
        return user_can($this->bound_user_id, 'manage_categories');
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
                'title' => html_entity_decode(get_bloginfo('name'), ENT_QUOTES, 'UTF-8'),
                'url'   => home_url(),
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
        $key_id = $this->matched_key_id;
        $label = null;
        if (!empty($key_id)) {
            $keys = get_option('connectmwp_keys', []);
            if (is_array($keys) && isset($keys[$key_id]) && !empty($keys[$key_id]['label'])) {
                $label = $keys[$key_id]['label'];
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

        $keys = get_option('connectmwp_keys', []);
        if (!is_array($keys)) {
            $keys = [];
        }
        $total_keys = count($keys);

        $latest_key_id  = null;
        $latest_created = null;
        $latest_label   = null;
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
     * Handle Public Key Enrollment
     */
    public function enroll_client_handler(WP_REST_Request $request) {
        // Enforce SSL unless it is localhost
        $client_ip = $this->get_client_ip();
        $is_localhost = in_array($client_ip, ['127.0.0.1', '::1', 'localhost'], true) || (isset($_SERVER['HTTP_HOST']) && preg_match('/localhost|\.local|\.test/i', $_SERVER['HTTP_HOST']));
        if (!is_ssl() && !$is_localhost) {
            return new WP_REST_Response(['success' => false, 'error' => 'HTTPS is required for enrollment.'], 403);
        }

        // Transient-based IP rate limiting
        $ip_key = 'cmwp_enroll_limit_' . md5($client_ip);
        $attempts = intval(get_transient($ip_key));
        if ($attempts >= 5) {
            return new WP_REST_Response(['success' => false, 'error' => 'Too many enrollment attempts. Please try again later.'], 429);
        }

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

        if (empty($custom_code)) {
            return new WP_REST_Response(['success' => false, 'error' => 'Enrollment code is required'], 401);
        }

        // Validate single-use enrollment code
        $stored = get_option('connectmwp_enrollment_code');
        if (!is_array($stored) || empty($stored['code']) || !hash_equals($stored['code'], $custom_code)) {
            set_transient($ip_key, $attempts + 1, 600); // Lock for 10 mins
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

        $key_id = 'cmwp_key_' . bin2hex(random_bytes(8));

        $keys = get_option('connectmwp_keys', []);
        if (!is_array($keys)) {
            $keys = [];
        }

        $keys[$key_id] = [
            'public_key'     => $public_key,
            'bound_user_id'  => intval($stored['user_id']),
            'label'          => $label,
            'created'        => current_time('mysql'),
            'last_used'      => '',
            'last_ip'        => ''
        ];

        update_option('connectmwp_keys', $keys, 'no');

        // Delete pairing code and rate-limit transient immediately on success
        delete_option('connectmwp_enrollment_code');
        delete_transient($ip_key);

        return new WP_REST_Response(
            $this->build_identity_payload($key_id, intval($stored['user_id']), $label),
            200
        );
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
     * REST Handlers
     */
    public function get_posts_handler(WP_REST_Request $request) {
        $limit = $request->get_param('limit') ? intval($request->get_param('limit')) : 50;
        $limit = min(100, max(1, $limit));
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

        // Check if reader has permission for draft
        if ($post->post_status === 'draft') {
            if ($post->post_author != $this->bound_user_id && !user_can($this->bound_user_id, 'edit_others_posts')) {
                return new WP_REST_Response(['success' => false, 'error' => 'Forbidden'], 403);
            }
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
        if (!$post) {
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

        if (!empty($_FILES['file']['size']) && $_FILES['file']['size'] > 10 * 1024 * 1024) {
            return new WP_REST_Response(['success' => false, 'error' => 'File size exceeds maximum limit of 10MB.'], 400);
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
        $limit = 50;
        $offset = 0;
        $search = '';
        if ($request instanceof WP_REST_Request) {
            $limit = $request->get_param('limit') ? intval($request->get_param('limit')) : 50;
            $offset = $request->get_param('offset') ? intval($request->get_param('offset')) : 0;
            $search = $request->get_param('search') ? sanitize_text_field($request->get_param('search')) : '';
        }
        $limit = min(200, max(1, $limit));
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
        return new WP_REST_Response(['success' => true, 'tags' => $result], 200);
    }

    public function get_categories_handler(?WP_REST_Request $request = null) {
        $limit = 50;
        $offset = 0;
        $search = '';
        if ($request instanceof WP_REST_Request) {
            $limit = $request->get_param('limit') ? intval($request->get_param('limit')) : 50;
            $offset = $request->get_param('offset') ? intval($request->get_param('offset')) : 0;
            $search = $request->get_param('search') ? sanitize_text_field($request->get_param('search')) : '';
        }
        $limit = min(200, max(1, $limit));
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
        return new WP_REST_Response(['success' => true, 'categories' => $result], 200);
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
            return new WP_REST_Response(['success' => false, 'error' => $term->get_error_message()], 400);
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
            return new WP_REST_Response(['success' => false, 'error' => $term->get_error_message()], 400);
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

        switch ($action) {
            case 'get_posts':
                if (!$this->check_read_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_posts_handler($request);
                break;
            case 'get_post':
                $request->set_param('id', isset($_REQUEST['post_id']) ? intval($_REQUEST['post_id']) : 0);
                if (!$this->check_read_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_post_handler($request);
                break;
            case 'create_post':
                if (!$this->check_edit_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->create_post_handler($request);
                break;
            case 'update_post':
                $request->set_param('id', isset($_REQUEST['post_id']) ? intval($_REQUEST['post_id']) : 0);
                if (!$this->check_edit_post_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->update_post_handler($request);
                break;
            case 'delete_post':
                $request->set_param('id', isset($_REQUEST['post_id']) ? intval($_REQUEST['post_id']) : 0);
                if (!$this->check_delete_post_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->delete_post_handler($request);
                break;
            case 'upload_media':
                if (!$this->check_upload_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->upload_media_handler($request);
                break;
            case 'get_tags':
                if (!$this->check_read_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_tags_handler($request);
                break;
            case 'get_categories':
                if (!$this->check_read_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_categories_handler($request);
                break;
            case 'create_category':
                if (!$this->check_taxonomy_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->create_category_handler($request);
                break;
            case 'create_tag':
                if (!$this->check_taxonomy_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->create_tag_handler($request);
                break;
            case 'whoami':
                // Signature already verified above; no further capability required.
                $res = $this->whoami_handler($request);
                break;
            default:
                wp_send_json_error(['error' => 'Invalid action'], 400);
        }

        wp_send_json($res->get_data(), $res->get_status());
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

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient privileges to access this page.'));
        }

        // Process revocation of keys
        if (isset($_POST['connectmwp_action']) && $_POST['connectmwp_action'] === 'revoke_key' && isset($_POST['key_id'])) {
            check_admin_referer('connectmwp_revoke_key');
            $key_id_to_revoke = sanitize_text_field($_POST['key_id']);
            $keys = get_option('connectmwp_keys', []);
            if (is_array($keys) && isset($keys[$key_id_to_revoke])) {
                unset($keys[$key_id_to_revoke]);
                update_option('connectmwp_keys', $keys, 'no');
                echo '<div class="notice notice-success is-dismissible"><p>Client key successfully revoked.</p></div>';
            }
        }

        // Process generation of pairing code
        if (isset($_POST['connectmwp_action']) && $_POST['connectmwp_action'] === 'generate_pairing') {
            check_admin_referer('connectmwp_generate_pairing');
            $this->generate_enrollment_code();
        }

        // Retrieve active pairing code if it exists and hasn't expired
        $enrollment_string = '';
        $stored = get_option('connectmwp_enrollment_code');
        if (is_array($stored) && !empty($stored['code']) && time() <= intval($stored['expires'])) {
            $enrollment_string = esc_url(home_url()) . ',' . $stored['code'];
        }

        $all_keys = get_option('connectmwp_keys', []);
        $all_keys_with_users = [];
        if (is_array($all_keys)) {
            foreach ($all_keys as $key_id => $key_data) {
                $user_info = get_userdata($key_data['bound_user_id']);
                $key_data['user_login'] = $user_info ? $user_info->user_login : 'Unknown User';
                $key_data['user_display'] = $user_info ? ($user_info->display_name ?: $user_info->user_login) : 'Unknown User';
                $key_data['user_roles'] = $user_info && is_array($user_info->roles) ? array_values($user_info->roles) : [];
                $key_data['key_id'] = $key_id;
                $all_keys_with_users[] = $key_data;
            }
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
        $stale_unused_threshold  = 7  * 86400;  // 7 days
        $stale_last_used_threshold = 30 * 86400; // 30 days
        $just_paired_threshold     = 3600;        // 1 hour
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
            $age_created   = $k['created_ts']   ? ($now - $k['created_ts'])   : 0;
            $age_last_used = $k['last_used_ts'] ? ($now - $k['last_used_ts']) : null;
            $k['is_just_paired'] = $k['created_ts'] && $age_created < $just_paired_threshold;
            $never_used = empty($k['last_used']);
            $k['is_stale'] = ($never_used && $age_created > $stale_unused_threshold) ||
                             ($age_last_used !== null && $age_last_used > $stale_last_used_threshold);
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
            .cmwp-tab { padding: 8px 14px; font-size: 13px; font-weight: 600; color: #7f8c8d; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px; transition: color 0.15s ease, border-color 0.15s ease; user-select: none; }
            .cmwp-tab.active { color: #3498db; border-bottom-color: #3498db; }
            .cmwp-tab:hover:not(.active) { color: #34495e; }
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
                <h1>🔌 connectMWP Agent <span class="cmwp-ver">v<?php echo esc_html(self::VERSION); ?></span></h1>
                <p>Secure, signature-based direct connector between local AI clients (Claude Desktop, Cursor, ChatGPT Desktop, Antigravity, etc.) and this WordPress site.</p>
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
                        <button type="button" class="cmwp-btn-copy" onclick="navigator.clipboard.writeText(document.getElementById('cmwp-enroll-cmd').value).then(() => showConnectMWPToast(this, 'Command copied!'))">Copy</button>
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
                                if (!res.ok) return;
                                const data = await res.json();
                                const claimed = (data.total_keys > initialTotal) || (data.latest_key_id && data.latest_key_id !== initialLatest);
                                if (claimed) {
                                    stopped = true;
                                    if (timer) clearInterval(timer);
                                    flipCardToSuccess(data.latest_label);
                                    setTimeout(function() { window.location.reload(); }, 1500);
                                    return;
                                }
                                if (!data.code_active) {
                                    stopped = true;
                                    if (timer) clearInterval(timer);
                                }
                            } catch (e) {}
                        }

                        poll();
                        timer = setInterval(poll, 3000);
                        document.addEventListener('visibilitychange', function() {
                            if (document.visibilityState === 'visible' && !stopped) poll();
                        });
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
                        <li><strong>Want to use this site from another AI client on the same Mac?</strong> (Claude Desktop, Cursor, ChatGPT Desktop, Antigravity, etc.) Register the same MCP server in each — <code>npx -y connectmwp-mcp</code>. They share this pairing; no new code needed.</li>
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
                    </div>
                </div>

                <div class="cmwp-tabs" id="cmwp-config-tabs">
                    <div class="cmwp-tab active" data-target="claude">Claude Desktop</div>
                    <div class="cmwp-tab" data-target="cursor">Cursor</div>
                    <div class="cmwp-tab" data-target="other">Other (ChatGPT Desktop, Cline, Continue…)</div>
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
                    For ChatGPT Desktop, Cline, Continue, or any other MCP-capable client: register a stdio MCP server named <code>connectmwp</code> with command <code>npx</code> and args <code>["-y", "connectmwp-mcp"]</code>. Exact menu paths vary by app.
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
                        navigator.clipboard.writeText(text).then(function() {
                            showConnectMWPToast(el, 'Key ID copied');
                        });
                    });
                });

                document.querySelectorAll('#cmwp-config-tabs .cmwp-tab').forEach(function(tab) {
                    tab.addEventListener('click', function() {
                        const target = tab.dataset.target;
                        document.querySelectorAll('#cmwp-config-tabs .cmwp-tab').forEach(function(t) {
                            t.classList.toggle('active', t === tab);
                        });
                        document.querySelectorAll('[data-pane]').forEach(function(p) {
                            p.style.display = (p.dataset.pane === target ? 'block' : 'none');
                        });
                        document.querySelectorAll('[data-tip]').forEach(function(p) {
                            p.style.display = (p.dataset.tip === target ? 'block' : 'none');
                        });
                    });
                });
            })();
            </script>
        </div>
        <?php
    }
}

// Instantiate
ConnectMWP_Agent::instance();

