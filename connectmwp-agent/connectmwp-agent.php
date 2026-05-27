<?php
/**
 * Plugin Name: connectMWP Agent
 * Plugin URI: https://connectmwp.com
 * Description: Secure remote connector for connectmwp.com. Exposes safe REST API and Admin-AJAX endpoints signed with client-level tokens.
 * Version: 2.0.6
 * Author: Stefan Heinz, 2morrow.ai
 * Author URI: https://2morrow.ai
 * License: GPLv2
 */

defined('ABSPATH') || exit;

class ConnectMWP_Agent {

    const VERSION = '2.0.6';
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

        // Admin-AJAX routes (Fallback endpoints)
        add_action('wp_ajax_connectmwp_api', [$this, 'handle_ajax_request']);
        add_action('wp_ajax_nopriv_connectmwp_api', [$this, 'handle_ajax_request']);

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

    private $signature_verified = null;
    private $bound_user_id = 0;
    private $matched_key_id = '';

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

        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'X-ConnectMWP-Key') === 0) {
                    $key_id = $value;
                } elseif (strcasecmp($name, 'X-ConnectMWP-Timestamp') === 0) {
                    $timestamp = $value;
                } elseif (strcasecmp($name, 'X-ConnectMWP-Signature') === 0) {
                    $signature_b64 = $value;
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

        if (empty($key_id) || empty($timestamp) || empty($signature_b64)) {
            $this->signature_verified = false;
            return false;
        }

        // 3. Verify timestamp skew (within ±300s)
        if (abs(time() - intval($timestamp)) > 300) {
            $this->signature_verified = false;
            return false;
        }

        // 4. Look up client key
        $key_config = $this->find_key_by_id($key_id);
        if (!$key_config) {
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

        // Body hash (skip hashing multipart/form-data body to avoid boundary mismatches)
        $raw_body = '';
        $content_type = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
        if (stripos($content_type, 'multipart/form-data') === false) {
            $raw_body = file_get_contents('php://input');
        }
        $body_hash = hash('sha256', $raw_body ?? '');

        $canonical = implode("\n", [
            $timestamp,
            strtoupper($method),
            $request_path,
            $query_hash,
            $body_hash
        ]);

        // 6. Verify signature using libsodium
        $pub_key_raw = base64_decode($pub_key_b64);
        $sig_raw = base64_decode($signature_b64);

        if (strlen($pub_key_raw) !== 32 || strlen($sig_raw) !== 64) {
            $this->signature_verified = false;
            return false;
        }

        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            $this->signature_verified = false;
            return false;
        }

        $verified = sodium_crypto_sign_verify_detached($sig_raw, $canonical, $pub_key_raw);
        if (!$verified) {
            $this->signature_verified = false;
            return false;
        }

        // 7. Replay attack check
        $sig_hash = hash('sha256', $signature_b64);
        if ($this->is_replay_signature($sig_hash)) {
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
        $claimed = get_option('connectmwp_claimed_signatures', []);
        if (!is_array($claimed)) {
            $claimed = [];
        }

        $now = time();

        // Prune expired signatures
        $changed = false;
        foreach ($claimed as $hash => $expiry) {
            if ($now > $expiry) {
                unset($claimed[$hash]);
                $changed = true;
            }
        }

        if (isset($claimed[$sig_hash])) {
            if ($changed) {
                update_option('connectmwp_claimed_signatures', $claimed, 'no');
            }
            return true;
        }

        // Enforce max size limit (500 entries)
        if (count($claimed) >= 500) {
            asort($claimed);
            array_shift($claimed);
        }

        $claimed[$sig_hash] = $now + 360;
        update_option('connectmwp_claimed_signatures', $claimed, 'no');

        return false;
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
            $keys[$key_id]['last_used'] = current_time('mysql');
            $keys[$key_id]['last_ip'] = $this->get_client_ip();
            update_option('connectmwp_keys', $keys, 'no');
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

    /**
     * Handle Public Key Enrollment
     */
    public function enroll_client_handler(WP_REST_Request $request) {
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

        // Delete pairing code immediately (single-use constraint)
        delete_option('connectmwp_enrollment_code');

        return new WP_REST_Response([
            'success' => true,
            'key_id'  => $key_id
        ], 200);
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
        ];

        // Scope drafts to own user if user lacks edit_others_posts
        if (!user_can($this->bound_user_id, 'edit_others_posts')) {
            $query_args['author'] = $this->bound_user_id;
        }

        $posts_query = new WP_Query($query_args);

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

        return new WP_REST_Response(['success' => true, 'posts' => $posts], 200);
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
            $requested_fields = ['id', 'title', 'url', 'link', 'status', 'date', 'content'];
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

    public function get_tags_handler() {
        $tags = get_tags(['hide_empty' => false]);
        $result = [];
        foreach ($tags as $tag) {
            $result[] = [
                'id'   => $tag->term_id,
                'name' => $tag->name,
                'slug' => $tag->slug,
            ];
        }
        return new WP_REST_Response(['success' => true, 'tags' => $result], 200);
    }

    public function get_categories_handler() {
        $categories = get_categories(['hide_empty' => false]);
        $result = [];
        foreach ($categories as $category) {
            $result[] = [
                'id'   => $category->term_id,
                'name' => $category->name,
                'slug' => $category->slug,
            ];
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
            wp_send_json_error(['error' => 'Unauthorized'], 401);
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
            case 'upload_media':
                if (!$this->check_upload_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->upload_media_handler($request);
                break;
            case 'get_tags':
                if (!$this->check_read_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_tags_handler();
                break;
            case 'get_categories':
                if (!$this->check_read_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_categories_handler();
                break;
            case 'create_category':
                if (!$this->check_taxonomy_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->create_category_handler($request);
                break;
            case 'create_tag':
                if (!$this->check_taxonomy_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->create_tag_handler($request);
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
                $key_data['key_id'] = $key_id;
                $all_keys_with_users[] = $key_data;
            }
        }

        ?>
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
        <div class="wrap" style="max-width: 900px; margin: 20px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;">
            
            <div style="background: linear-gradient(135deg, #2c3e50, #3498db); padding: 30px; border-radius: 12px; color: #fff; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); margin-bottom: 25px; position: relative; overflow: hidden;">
                <div style="position: absolute; right: -50px; top: -50px; width: 200px; height: 200px; border-radius: 50%; background: rgba(255,255,255,0.05);"></div>
                <div style="position: absolute; right: 50px; bottom: -80px; width: 150px; height: 150px; border-radius: 50%; background: rgba(255,255,255,0.03);"></div>
                
                <h1 style="color: #fff; margin: 0 0 8px 0; font-size: 28px; font-weight: 700; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 32px;">🔌</span> connectMWP Agent <span style="font-size: 13px; font-weight: 400; opacity: 0.8; background: rgba(255,255,255,0.15); padding: 3px 10px; border-radius: 20px; vertical-align: middle;">v<?php echo esc_html(self::VERSION); ?></span>
                </h1>
                <p style="margin: 0; font-size: 16px; opacity: 0.9; line-height: 1.4;">
                    Secure, signature-based direct connector between local AI clients (Claude Desktop, Cursor, etc.) and this WordPress site.
                </p>
            </div>

            <?php if ($enrollment_string): ?>
                <?php
                $npx_cmd = 'npx -y connectmwp-mcp add-site --enroll "' . $enrollment_string . '"';
                $stored = get_option('connectmwp_enrollment_code');
                $remaining = is_array($stored) && isset($stored['expires']) ? intval($stored['expires']) - time() : 600;
                $remaining = max(0, $remaining);
                ?>
                <div style="background: #fff; border: 1px solid #e1e8ed; border-left: 6px solid #e74c3c; border-radius: 12px; padding: 25px; margin-bottom: 25px; box-shadow: 0 10px 30px rgba(231, 76, 60, 0.12); position: relative; animation: fadeIn 0.4s ease-out;">
                    <div style="position: absolute; top: 15px; right: 15px; display: flex; align-items: center; gap: 10px;">
                        <span style="background: #fff3cd; border: 1px solid #ffeeba; color: #d35400; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; display: inline-flex; align-items: center; gap: 4px;">
                            ⏳ Expiring: <span id="connectmwp-countdown" style="font-family: monospace; font-size: 12px;">--:--</span>
                        </span>
                        <span style="background: rgba(231, 76, 60, 0.1); color: #e74c3c; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;">One-Time Pairing Code</span>
                    </div>
                    
                    <h3 style="color: #c0392b; margin: 0 0 15px 0; font-size: 18px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                        ⚠️ Action Required: Go Pair Your Local Environment Now
                    </h3>

                    <div style="background: #fdfefe; border: 1px solid #eaeded; border-left: 3px solid #3498db; border-radius: 6px; padding: 15px; margin-bottom: 20px; font-size: 13.5px; color: #34495e; line-height: 1.6;">
                        <strong style="color: #2c3e50; font-size: 14px; display: block; margin-bottom: 8px;">👉 How to Pair:</strong>
                        <ol style="margin: 0; padding-left: 20px; list-style-type: decimal;">
                            <li>Open a <strong>Terminal</strong> window on your local computer.</li>
                            <li>Ensure you have <strong>Node.js (v18+)</strong> installed (verify by running <code>node -v</code> in the terminal).</li>
                            <li>Copy and run the <strong>Terminal Pairing Command</strong> below.</li>
                            <li>Once the terminal reports success (<code>[SUCCESS] Client paired and enrolled successfully!</code>), **refresh this page** to see your client registered in the <strong>Paired Clients</strong> list below.</li>
                        </ol>
                    </div>
                    
                    <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
                        <div style="font-size: 12px; font-weight: 600; text-transform: uppercase; color: #7f8c8d; margin-bottom: 5px;">Pairing Enrollment String</div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <code style="font-family: monospace; font-size: 14px; background: #eef1f6; padding: 6px 12px; border-radius: 4px; color: #2c3e50; font-weight: 600; word-break: break-all; width: 100%; border: 1px solid #d5dbdb;"><?php echo esc_html($enrollment_string); ?></code>
                            <button type="button" class="button" onclick="navigator.clipboard.writeText('<?php echo esc_js($enrollment_string); ?>').then(() => showConnectMWPToast(this, 'Enrollment string copied!'))" style="white-space: nowrap; height: 35px;">Copy String</button>
                        </div>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px;">
                            💻 Terminal Pairing Command (npx)
                        </div>
                        <div style="display: flex; gap: 10px; align-items: stretch;">
                            <textarea readonly style="font-family: monospace; font-size: 12px; background: #2c3e50; color: #ecf0f1; padding: 12px; border-radius: 6px; border: none; width: 100%; height: 60px; resize: none; line-height: 1.4; box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);" id="claude-enroll-cmd"><?php echo esc_textarea($npx_cmd); ?></textarea>
                            <button type="button" class="button button-primary" onclick="navigator.clipboard.writeText(document.getElementById('claude-enroll-cmd').value).then(() => showConnectMWPToast(this, 'Command copied!'))" style="height: 60px; background: #34495e; border-color: #2c3e50; border-radius: 6px;">Copy Command</button>
                        </div>
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
                </div>
            <?php endif; ?>

            <div style="display: grid; grid-template-columns: 1fr; gap: 25px;">
                
                <div style="background: #fff; border: 1px solid #e1e8ed; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.02);">
                    <h2 style="margin-top: 0; margin-bottom: 15px; font-size: 18px; font-weight: 600; color: #2c3e50; border-bottom: 1px solid #f0f3f4; padding-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span>🔑</span> Pair Local Client
                    </h2>
                    <p style="font-size: 14px; color: #7f8c8d; line-height: 1.5; margin-bottom: 20px;">
                        Generate a single-use pairing code to connect your local MCP server to this site. During pairing, your local client will generate an Ed25519 cryptographic keypair and upload its public key.
                    </p>
                    
                    <form method="post" action="">
                        <?php wp_nonce_field('connectmwp_generate_pairing'); ?>
                        <input type="hidden" name="connectmwp_action" value="generate_pairing" />
                        <button type="submit" class="button button-primary" style="background: #3498db; border-color: #2980b9; box-shadow: 0 2px 4px rgba(52, 152, 219, 0.2); font-weight: 600; font-size: 14px; padding: 4px 20px; height: auto; min-height: 38px; border-radius: 6px;">Generate Pairing Code</button>
                    </form>
                </div>

                <div style="background: #fff; border: 1px solid #e1e8ed; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.02);">
                    <h2 style="margin-top: 0; margin-bottom: 15px; font-size: 18px; font-weight: 600; color: #2c3e50; border-bottom: 1px solid #f0f3f4; padding-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span>🛡️</span> Paired Clients
                    </h2>
                    
                    <?php if (empty($all_keys_with_users)): ?>
                        <p style="font-size: 14px; color: #7f8c8d; line-height: 1.5; margin: 10px 0;">No paired clients found.</p>
                    <?php else: ?>
                        <table class="wp-list-table widefat fixed striped" style="border: none; box-shadow: none; margin-top: 10px;">
                            <thead>
                                <tr>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50; width: 25%;">Client Label</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50; width: 25%;">Key ID</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50; width: 15%;">WP User</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50; width: 15%;">Created</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50; width: 20%; text-align: right;">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($all_keys_with_users as $key_data): ?>
                                    <tr>
                                        <td style="padding: 12px 10px; vertical-align: middle;"><strong><?php echo esc_html($key_data['label']); ?></strong></td>
                                        <td style="padding: 12px 10px; vertical-align: middle; font-family: monospace; font-size: 12px;"><?php echo esc_html($key_data['key_id']); ?></td>
                                        <td style="padding: 12px 10px; vertical-align: middle;"><?php echo esc_html($key_data['user_login']); ?></td>
                                        <td style="padding: 12px 10px; vertical-align: middle; color: #7f8c8d; font-size: 12px;"><?php echo esc_html($key_data['created']); ?></td>
                                        <td style="padding: 12px 10px; vertical-align: middle; text-align: right;">
                                            <form method="post" style="display:inline;">
                                                <?php wp_nonce_field('connectmwp_revoke_key'); ?>
                                                <input type="hidden" name="connectmwp_action" value="revoke_key" />
                                                <input type="hidden" name="key_id" value="<?php echo esc_attr($key_data['key_id']); ?>" />
                                                <button type="submit" class="button button-link-delete" onclick="return confirm('Are you sure you want to revoke this client\'s access?');" style="color: #d63638; border-color: #ccd0d4; padding: 2px 10px; height: auto;">Revoke Access</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>

                <!-- Card: IDE Configuration -->
                <div style="background: #fff; border: 1px solid #e1e8ed; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.02); margin-top: 25px;">
                    <h2 style="margin-top: 0; margin-bottom: 15px; font-size: 18px; font-weight: 600; color: #2c3e50; border-bottom: 1px solid #f0f3f4; padding-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span>⚙️</span> IDE & Client Configuration (Cursor, Claude Desktop, etc.)
                    </h2>
                    <p style="font-size: 14px; color: #7f8c8d; line-height: 1.5; margin-bottom: 20px;">
                        Once you pair this machine via the terminal pairing command above, the connection is established globally for your user profile. To register the MCP server in your IDE, add the following configuration block to your settings file.
                    </p>
                    
                    <div style="margin-bottom: 20px;">
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px;">
                            📋 Cursor IDE Configuration (Settings -> Features -> MCP)
                        </div>
                        <div style="font-size: 12px; color: #7f8c8d; margin-bottom: 12px; line-height: 1.4;">
                            💡 <strong>Integration Tip:</strong> If you already have other MCP servers configured, copy and merge only the <strong style="color: #2980b9;">highlighted block</strong> inside your existing <code>"mcpServers"</code> object (remember to add a comma between servers).
                        </div>
                        <pre style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 12px; color: #2c3e50; overflow-x: auto; line-height: 1.4; margin: 0;"><span style="color: #abb2b9;">{
  "mcpServers": {</span>
<span style="font-weight: 700; color: #1f618d;">    "connectmwp": {
      "command": "npx",
      "args": [
        "-y",
        "connectmwp-mcp"
      ]
    }</span>
<span style="color: #abb2b9;">  }
}</span></pre>
                    </div>

                    <div>
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px;">
                            📋 Claude Desktop Configuration (claude_desktop_config.json)
                        </div>
                        <div style="font-size: 12px; color: #7f8c8d; margin-bottom: 12px; line-height: 1.4;">
                            💡 <strong>Integration Tip:</strong> If you already have other MCP servers configured, copy and merge only the <strong style="color: #2980b9;">highlighted block</strong> inside your existing <code>"mcpServers"</code> object (remember to add a comma between servers).
                        </div>
                        <pre style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 12px; color: #2c3e50; overflow-x: auto; line-height: 1.4; margin: 0;"><span style="color: #abb2b9;">{
  "mcpServers": {</span>
<span style="font-weight: 700; color: #1f618d;">    "connectmwp": {
      "command": "npx",
      "args": [
        "-y",
        "connectmwp-mcp"
      ]
    }</span>
<span style="color: #abb2b9;">  }
}</span></pre>
                    </div>
                </div>
            </div>
            
            <style>
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            </style>
        </div>
        <?php
    }
}

// Instantiate
ConnectMWP_Agent::instance();
