<?php
/**
 * Plugin Name: connectMWP Agent
 * Plugin URI: https://connectmwp.com
 * Description: Secure remote connector for connectmwp.com. Exposes safe REST API and Admin-AJAX endpoints signed with client-level tokens.
 * Version: 1.2.3
 * Author: Stefan Heinz, 2morrow.ai
 * Author URI: https://2morrow.ai
 * License: GPLv2
 */

defined('ABSPATH') || exit;

class ConnectMWP_Agent {

    const OPTION_TOKENS = 'connectmwp_agent_tokens';
    const OPTION_NONCES = 'connectmwp_agent_nonces';
    const API_NAMESPACE = 'connectmwp/v1';

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Authenticate request early
        add_filter('determine_current_user', [$this, 'authenticate_request'], 5);

        // Register endpoints
        add_action('rest_api_init', [$this, 'register_rest_routes']);

        // Admin-AJAX routes
        add_action('wp_ajax_connectmwp_api', [$this, 'handle_ajax_request']);
        add_action('wp_ajax_nopriv_connectmwp_api', [$this, 'handle_ajax_request']);

        // Admin pages
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'handle_oauth_approve']);

        // Allowed hosts for safe redirects (C-1)
        add_filter('allowed_redirect_hosts', [$this, 'filter_allowed_redirect_hosts']);
    }

    /**
     * Authenticate remote requests using the custom X-ConnectMWP-Auth header
     */
    public function authenticate_request($user_id) {
        if ($user_id) {
            return $user_id;
        }

        $token = $this->get_auth_token_from_header();
        if (empty($token)) {
            return $user_id;
        }

        // 1. Search for matching token in database FIRST (C-3 Fix)
        $token_hash = hash('sha256', $token);
        $user_id_found = $this->find_user_by_token_hash($token_hash);

        if (!$user_id_found) {
            return $user_id;
        }

        // 2. Validate replay attack prevention (only for valid tokens)
        if (!$this->validate_replay_headers()) {
            return 0; // Deny auth if replay validation fails
        }

        $this->update_token_last_used($user_id_found, $token_hash);
        return $user_id_found;
    }

    private function get_auth_token_from_header() {
        $custom_auth = '';
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'X-ConnectMWP-Auth') === 0) {
                    $custom_auth = $value;
                    break;
                }
            }
        }

        if (empty($custom_auth) && isset($_SERVER['HTTP_X_CONNECTMWP_AUTH'])) {
            $custom_auth = $_SERVER['HTTP_X_CONNECTMWP_AUTH'];
        }

        if (empty($custom_auth)) {
            return '';
        }

        // Support both "Bearer [token]" and "[token]" formats
        if (strpos(strtolower($custom_auth), 'bearer ') === 0) {
            return substr($custom_auth, 7);
        }

        return $custom_auth;
    }

    /**
     * Validate request timestamp and nonce for replay protection
     */
    private function validate_replay_headers() {
        $timestamp = '';
        $nonce = '';

        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'X-ConnectMWP-Timestamp') === 0) {
                    $timestamp = $value;
                } elseif (strcasecmp($name, 'X-ConnectMWP-Nonce') === 0) {
                    $nonce = $value;
                }
            }
        }

        if (empty($timestamp) && isset($_SERVER['HTTP_X_CONNECTMWP_TIMESTAMP'])) {
            $timestamp = $_SERVER['HTTP_X_CONNECTMWP_TIMESTAMP'];
        }
        if (empty($nonce) && isset($_SERVER['HTTP_X_CONNECTMWP_NONCE'])) {
            $nonce = $_SERVER['HTTP_X_CONNECTMWP_NONCE'];
        }

        // If either is missing, fail validation
        if (empty($timestamp) || empty($nonce)) {
            return false;
        }

        // Verify timestamp is within 5 minutes (300 seconds)
        if (abs(time() - intval($timestamp)) > 300) {
            return false;
        }

        // Sanitize nonce and check atomically via individual transient options (C-3 / I-1 Fix)
        $nonce_hash = md5($nonce);
        $nonce_key = 'cmwp_nonce_' . $nonce_hash;

        $expiry = time() + 360;
        // add_option returns false if the option already exists
        if (!add_option($nonce_key, $expiry, '', 'no')) {
            return false; // Nonce already claimed (replay attack or race condition)
        }

        // Prune expired nonces (100% probability, safe as it only runs for authenticated requests)
        global $wpdb;
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'cmwp_nonce_%' AND option_value < %d",
            time()
        ));

        return true;
    }

    private function find_user_by_token_hash($token_hash) {
        $users = get_users([
            'meta_key'     => '_connectmwp_tokens',
            'meta_value'   => $token_hash,
            'meta_compare' => 'LIKE',
            'number'       => 1
        ]);

        if (empty($users)) {
            return false;
        }

        $user = $users[0];
        $tokens = get_user_meta($user->ID, '_connectmwp_tokens', true);
        if (is_array($tokens)) {
            foreach ($tokens as $token) {
                if (isset($token['hash']) && hash_equals($token['hash'], $token_hash)) {
                    return $user->ID;
                }
            }
        }

        return false;
    }

    private function update_token_last_used($user_id, $token_hash) {
        $tokens = get_user_meta($user_id, '_connectmwp_tokens', true);
        if (is_array($tokens)) {
            $updated = false;
            foreach ($tokens as $key => $token) {
                if (isset($token['hash']) && hash_equals($token['hash'], $token_hash)) {
                    $tokens[$key]['last_used'] = current_time('mysql');
                    $tokens[$key]['last_ip'] = $this->get_client_ip();
                    $updated = true;
                    break;
                }
            }
            if ($updated) {
                update_user_meta($user_id, '_connectmwp_tokens', $tokens);
            }
        }
    }

    private function get_client_ip() {
        if (!empty($_SERVER['REMOTE_ADDR']) && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
            return $_SERVER['REMOTE_ADDR'];
        }
        return 'unknown';
    }

    /**
     * Register Custom WordPress REST API Routes
     */
    public function register_rest_routes() {
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
            ]
        ]);

        register_rest_route(self::API_NAMESPACE, '/categories', [
            [
                'methods'             => 'GET',
                'callback'            => [$this, 'get_categories_handler'],
                'permission_callback' => [$this, 'check_read_permission'],
            ]
        ]);
    }

    /**
     * Allowed redirect hosts for OAuth callback (C-1)
     */
    public function filter_allowed_redirect_hosts($hosts) {
        $hosts[] = 'connectmwp.com';
        $hosts[] = 'connect-mwp.vercel.app';
        return $hosts;
    }

    /**
     * Check if callback host is authorized (C-1)
     */
    private function is_allowed_callback($callback) {
        if (empty($callback)) {
            return false;
        }
        $host = wp_parse_url($callback, PHP_URL_HOST);
        if (!$host) {
            return false;
        }
        $host = strtolower($host);
        $allowed = ['connectmwp.com', 'connect-mwp.vercel.app'];
        return in_array($host, $allowed, true);
    }

    // Permission callbacks
    public function check_read_permission() {
        return is_user_logged_in() && current_user_can('edit_posts');
    }

    public function check_edit_permission() {
        return is_user_logged_in() && current_user_can('edit_posts');
    }

    public function check_edit_post_permission(WP_REST_Request $request) {
        $post_id = $request['id'];
        return is_user_logged_in() && current_user_can('edit_post', $post_id);
    }

    public function check_upload_permission() {
        return is_user_logged_in() && current_user_can('upload_files');
    }

    // Handlers
    public function get_posts_handler(WP_REST_Request $request) {
        $limit = $request->get_param('limit') ? intval($request->get_param('limit')) : 50;
        // Clamp query limit to [1, 100] (H-4 Fix)
        $limit = min(100, max(1, $limit));
        
        // Parse requested fields (SSOT Over-fetching Fix)
        $fields_param = $request->get_param('fields');
        if ($fields_param) {
            $requested_fields = array_map('trim', explode(',', strtolower($fields_param)));
        } else {
            // Default fields exclude the heavy content body
            $requested_fields = ['id', 'title', 'url', 'status', 'date'];
        }
        
        $query_args = [
            'post_type'      => 'post',
            'post_status'    => ['publish', 'draft'],
            'posts_per_page' => $limit,
        ];

        // Scope drafts to own user if user lacks edit_others_posts (H-2 Fix)
        if (!current_user_can('edit_others_posts')) {
            $query_args['author'] = get_current_user_id();
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
            if (in_array('url', $requested_fields, true)) {
                $post_item['url'] = get_permalink($post->ID);
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

        // Contributor publish privilege check (H-1 Fix)
        if ($status === 'publish' && !current_user_can('publish_posts')) {
            $status = 'pending';
        }

        $post_id = wp_insert_post([
            'post_title'     => $title,
            'post_content'   => $content,
            'post_status'    => $status,
            'post_category'  => $categories,
            'tags_input'     => $tags,
        ]);

        if (is_wp_error($post_id)) {
            error_log('connectMWP error inserting post: ' . $post_id->get_error_message());
            return new WP_REST_Response(['success' => false, 'error' => 'Failed to create post. Check site logs.'], 500);
        }

        // Validate featured media exists and is attachment type (API1 Ownership/Validation Check)
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
            // Contributor publish privilege check (H-1 Fix)
            if ($status === 'publish' && !current_user_can('publish_posts')) {
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
            error_log('connectMWP error updating post: ' . $updated_id->get_error_message());
            return new WP_REST_Response(['success' => false, 'error' => 'Failed to update post. Check site logs.'], 500);
        }

        // Validate featured media exists and is attachment type (API1 Ownership/Validation Check)
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

        // Check if file is uploaded
        if (empty($_FILES['file'])) {
            return new WP_REST_Response(['success' => false, 'error' => 'No file uploaded'], 400);
        }

        // Enforce server-side size limit of 10MB (10 * 1024 * 1024 bytes) (API4 Fix)
        if (!empty($_FILES['file']['size']) && $_FILES['file']['size'] > 10 * 1024 * 1024) {
            return new WP_REST_Response(['success' => false, 'error' => 'File size exceeds maximum limit of 10MB.'], 400);
        }

        // Perform the upload
        $attachment_id = media_handle_upload('file', 0); // 0 means unattached

        if (is_wp_error($attachment_id)) {
            error_log('connectMWP error uploading media: ' . $attachment_id->get_error_message());
            return new WP_REST_Response(['success' => false, 'error' => 'Failed to upload media. Check site logs.'], 500);
        }

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

    /**
     * Admin-AJAX Handler (Fallback endpoint)
     */
    public function handle_ajax_request() {
        // Simple bridge from AJAX to REST endpoints
        $action = isset($_REQUEST['connectmwp_action']) ? sanitize_key($_REQUEST['connectmwp_action']) : '';
        if (empty($action)) {
            wp_send_json_error(['error' => 'Missing action'], 400);
        }

        // Perform Early Auth since filter might not trigger fully in AJAX non-GET contexts
        $user_id = $this->authenticate_request(0);
        if ($user_id) {
            wp_set_current_user($user_id);
        }

        // Verify standard cap checks depending on actions
        if (!is_user_logged_in()) {
            wp_send_json_error(['error' => 'Unauthorized'], 401);
        }

        // Route calls to corresponding REST callbacks
        // For brevity, the bridge translates AJAX arguments and formats output
        $request = new WP_REST_Request($_SERVER['REQUEST_METHOD']);
        foreach ($_REQUEST as $k => $v) {
            if ($k !== 'action' && $k !== 'connectmwp_action') {
                $request->set_param($k, $v);
            }
        }

        switch ($action) {
            case 'get_posts':
                if (!$this->check_read_permission()) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_posts_handler($request);
                break;
            case 'create_post':
                if (!$this->check_edit_permission()) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->create_post_handler($request);
                break;
            case 'update_post':
                $request->set_param('id', isset($_REQUEST['post_id']) ? intval($_REQUEST['post_id']) : 0);
                if (!$this->check_edit_post_permission($request)) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->update_post_handler($request);
                break;
            case 'upload_media':
                if (!$this->check_upload_permission()) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->upload_media_handler($request);
                break;
            case 'get_tags':
                if (!$this->check_read_permission()) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_tags_handler();
                break;
            case 'get_categories':
                if (!$this->check_read_permission()) wp_send_json_error(['error' => 'Forbidden'], 403);
                $res = $this->get_categories_handler();
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

        // Register the hidden auth page slug so WordPress permits access to it
        add_submenu_page(
            null,
            'Authorize connectMWP',
            'Authorize connectMWP',
            'edit_posts',
            'connectmwp-auth',
            [$this, 'render_oauth_screen']
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // Process revocation
        if (isset($_POST['connectmwp_action']) && $_POST['connectmwp_action'] === 'revoke' && isset($_POST['token_hash'])) {
            check_admin_referer('connectmwp_revoke_token');
            $hash_to_revoke = sanitize_text_field($_POST['token_hash']);
            $this->revoke_token_globally($hash_to_revoke);
            echo '<div class="notice notice-success is-dismissible"><p>Token successfully revoked.</p></div>';
        }

        // Process manual token generation
        $new_token_data = null;
        if (isset($_POST['connectmwp_action']) && $_POST['connectmwp_action'] === 'generate' && isset($_POST['token_name'])) {
            check_admin_referer('connectmwp_generate_token');
            $token_name = sanitize_text_field($_POST['token_name']);
            
            $raw_token = 'connectmwp_tk_' . bin2hex(random_bytes(24));
            $token_hash = hash('sha256', $raw_token);
            
            $user = wp_get_current_user();
            $tokens = get_user_meta($user->ID, '_connectmwp_tokens', true);
            if (!is_array($tokens)) {
                $tokens = [];
            }
            
            $tokens[] = [
                'name'      => $token_name,
                'hash'      => $token_hash,
                'created'   => current_time('mysql'),
                'last_used' => '',
                'last_ip'   => '',
            ];
            
            update_user_meta($user->ID, '_connectmwp_tokens', $tokens);
            
            $new_token_data = [
                'raw_token' => $raw_token,
                'name'      => $token_name,
                'site_url'  => esc_url(home_url())
            ];
        }

        $users = get_users([
            'meta_key'     => '_connectmwp_tokens',
            'meta_compare' => 'EXISTS'
        ]);

        $all_tokens = [];
        foreach ($users as $user) {
            $tokens = get_user_meta($user->ID, '_connectmwp_tokens', true);
            if (is_array($tokens)) {
                foreach ($tokens as $token) {
                    $token['user_login'] = $user->user_login;
                    $token['user_id'] = $user->ID;
                    $all_tokens[] = $token;
                }
            }
        }

        ?>
        <div class="wrap" style="max-width: 900px; margin: 20px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;">
            
            <!-- Header Banner with subtle gradient -->
            <div style="background: linear-gradient(135deg, #2c3e50, #3498db); padding: 30px; border-radius: 12px; color: #fff; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); margin-bottom: 25px; position: relative; overflow: hidden;">
                <!-- Decorative subtle mesh/circles -->
                <div style="position: absolute; right: -50px; top: -50px; width: 200px; height: 200px; border-radius: 50%; background: rgba(255,255,255,0.05);"></div>
                <div style="position: absolute; right: 50px; bottom: -80px; width: 150px; height: 150px; border-radius: 50%; background: rgba(255,255,255,0.03);"></div>
                
                <h1 style="color: #fff; margin: 0 0 8px 0; font-size: 28px; font-weight: 700; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 32px;">🔌</span> connectMWP Agent <span style="font-size: 13px; font-weight: 400; opacity: 0.8; background: rgba(255,255,255,0.15); padding: 3px 10px; border-radius: 20px; vertical-align: middle;">v1.2.3</span>
                </h1>
                <p style="margin: 0; font-size: 16px; opacity: 0.9; line-height: 1.4;">
                    Secure, direct connection bridge between your local AI platforms (Claude Desktop, Cursor, etc.) and this WordPress site.
                </p>
            </div>

            <!-- If new token was generated, show the gorgeous one-time display box -->
            <?php if ($new_token_data): ?>
                <?php
                $site_url = $new_token_data['site_url'];
                $raw_token = $new_token_data['raw_token'];
                $claude_cmd = 'claude mcp add connectmwp npx -y connectmwp-mcp';
                $add_site_cmd = 'npx -y connectmwp-mcp add-site --site "' . $site_url . '" --token "' . $raw_token . '"';
                
                $cursor_config = json_encode([
                    'mcpServers' => [
                        'connectmwp' => [
                            'command' => 'npx',
                            'args' => [
                                '-y',
                                'connectmwp-mcp'
                            ]
                        ]
                    ]
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                ?>
                <div style="background: #fff; border: 1px solid #e1e8ed; border-left: 6px solid #e74c3c; border-radius: 12px; padding: 25px; margin-bottom: 25px; box-shadow: 0 10px 30px rgba(231, 76, 60, 0.12); position: relative; animation: fadeIn 0.4s ease-out;">
                    <div style="position: absolute; top: 15px; right: 15px;">
                        <span style="background: rgba(231, 76, 60, 0.1); color: #e74c3c; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;">One-Time Display</span>
                    </div>
                    
                    <h3 style="color: #c0392b; margin: 0 0 12px 0; font-size: 18px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                        ⚠️ Security Alert: Copy Connection Credentials Now
                    </h3>
                    <p style="font-size: 14px; color: #555; line-height: 1.5; margin-bottom: 20px;">
                        For your security, this raw connection token is stored in the database as a SHA-256 hash. <strong>It cannot be displayed again.</strong> Please copy the configuration below now.
                    </p>
                    
                    <!-- Token -->
                    <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
                        <div style="font-size: 12px; font-weight: 600; text-transform: uppercase; color: #7f8c8d; margin-bottom: 5px;">Connection Token</div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <code style="font-family: monospace; font-size: 15px; background: #eef1f6; padding: 6px 12px; border-radius: 4px; color: #2c3e50; font-weight: 600; word-break: break-all; width: 100%; border: 1px solid #d5dbdb;"><?php echo esc_html($raw_token); ?></code>
                            <button type="button" class="button" onclick="navigator.clipboard.writeText('<?php echo esc_js($raw_token); ?>').then(() => alert('Token copied!'))" style="white-space: nowrap; height: 35px;">Copy Token</button>
                        </div>
                    </div>

                    <!-- Step 1: Register Server -->
                    <div style="margin-bottom: 20px;">
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px; display: flex; align-items: center; gap: 5px;">
                            💻 Step 1: Register connectMWP in Claude (Run Once Globally)
                        </div>
                        
                        <!-- Interactive Scope Selector -->
                        <div style="margin-bottom: 12px; display: flex; gap: 15px; align-items: center; background: #f8f9fa; padding: 10px 15px; border-radius: 6px; border: 1px solid #e9ecef;">
                            <span style="font-size: 12px; font-weight: 600; text-transform: uppercase; color: #7f8c8d;">Command Scope:</span>
                            <label style="display: flex; align-items: center; gap: 5px; font-size: 13px; cursor: pointer; font-weight: 500; color: #2c3e50; margin: 0;">
                                <input type="radio" name="claude_scope" value="local" checked onclick="updateClaudeScope('local')" style="margin: 0;" />
                                Project Local (Default)
                            </label>
                            <label style="display: flex; align-items: center; gap: 5px; font-size: 13px; cursor: pointer; font-weight: 500; color: #2c3e50; margin: 0;">
                                <input type="radio" name="claude_scope" value="user" onclick="updateClaudeScope('user')" style="margin: 0;" />
                                Global User
                            </label>
                            <label style="display: flex; align-items: center; gap: 5px; font-size: 13px; cursor: pointer; font-weight: 500; color: #2c3e50; margin: 0;">
                                <input type="radio" name="claude_scope" value="project" onclick="updateClaudeScope('project')" style="margin: 0;" />
                                Shared Project (Team)
                            </label>
                        </div>

                        <div style="display: flex; gap: 10px; align-items: stretch;">
                            <textarea readonly style="font-family: monospace; font-size: 12px; background: #2c3e50; color: #ecf0f1; padding: 12px; border-radius: 6px; border: none; width: 100%; height: 60px; resize: none; line-height: 1.4; box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);" id="claude-cmd-text"><?php echo esc_textarea($claude_cmd); ?></textarea>
                            <button type="button" class="button button-primary" onclick="document.getElementById('claude-cmd-text').select(); document.execCommand('copy'); alert('CLI command copied!');" style="height: 60px; background: #34495e; border-color: #2c3e50; border-radius: 6px;">Copy Command</button>
                        </div>
                    </div>

                    <!-- Step 2: Link Site -->
                    <div style="margin-bottom: 25px;">
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px;">
                            🔗 Step 2: Link This WordPress Site (Run per WordPress Site)
                        </div>
                        <p style="font-size: 12px; color: #7f8c8d; margin-top: 0; margin-bottom: 8px;">Run this command once in your terminal to save this site's credentials to your local config file.</p>
                        <div style="display: flex; gap: 10px; align-items: stretch;">
                            <textarea readonly style="font-family: monospace; font-size: 12px; background: #2c3e50; color: #ecf0f1; padding: 12px; border-radius: 6px; border: none; width: 100%; height: 60px; resize: none; line-height: 1.4; box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);" id="claude-add-site-text"><?php echo esc_textarea($add_site_cmd); ?></textarea>
                            <button type="button" class="button button-primary" onclick="document.getElementById('claude-add-site-text').select(); document.execCommand('copy'); alert('Site linking command copied!');" style="height: 60px; background: #34495e; border-color: #2c3e50; border-radius: 6px;">Copy Command</button>
                        </div>
                    </div>

                    <script>
                    function updateClaudeScope(scope) {
                        let cmd = "claude mcp add ";
                        if (scope === "user") {
                            cmd += "--scope user ";
                        } else if (scope === "project") {
                            cmd += "--scope project ";
                        }
                        cmd += 'connectmwp npx -y connectmwp-mcp';
                        document.getElementById('claude-cmd-text').value = cmd;
                    }
                    </script>

                    <!-- Cursor Config -->
                    <div style="margin-bottom: 20px;">
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px;">
                            🛠️ Cursor IDE / Alternative MCP Client Config (JSON)
                        </div>
                        <div style="position: relative; margin-bottom: 8px;">
                            <pre style="margin: 0; background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 12px; line-height: 1.4; overflow-x: auto; box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);"><code id="cursor-config-code"><?php echo esc_html($cursor_config); ?></code></pre>
                            <button type="button" class="button" onclick="const code = document.getElementById('cursor-config-code').innerText; navigator.clipboard.writeText(code).then(() => alert('Cursor Config JSON copied!'))" style="position: absolute; top: 10px; right: 10px; background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.2); color: #fff; text-shadow: none;">Copy JSON</button>
                        </div>
                        <p style="font-size: 12px; color: #7f8c8d; margin: 0;">*Note: After adding the Cursor config, you must run the **Step 2** terminal command once to link this site's credentials.*</p>
                    </div>
                    
                    <!-- Dev Tip -->
                    <div style="margin-top: 25px; font-size: 13px; color: #31708f; background: #d9edf7; border: 1px solid #bce8f1; border-radius: 6px; padding: 15px; line-height: 1.5; display: flex; align-items: flex-start; gap: 8px;">
                        <span style="font-size: 16px;">💡</span>
                        <div>
                            <strong>Local Development Tip:</strong> Since <code>connectmwp-mcp</code> is not yet published to npm, you can use the local path of your index.js file:
                            <ul style="margin: 5px 0 0 15px; padding: 0; list-style-type: disc;">
                                <li><strong>Register Server (Step 1):</strong> Replace <code>npx -y connectmwp-mcp</code> with <code>node /path/to/connectmwp-mcp/index.js</code></li>
                                <li><strong>Link Site (Step 2):</strong> Replace <code>npx -y connectmwp-mcp</code> with <code>node /path/to/connectmwp-mcp/index.js</code></li>
                            </ul>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <div style="display: grid; grid-template-columns: 1fr; gap: 25px;">
                
                <!-- Card: Generate Token -->
                <div style="background: #fff; border: 1px solid #e1e8ed; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.02);">
                    <h2 style="margin-top: 0; margin-bottom: 15px; font-size: 18px; font-weight: 600; color: #2c3e50; border-bottom: 1px solid #f0f3f4; padding-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span>🔑</span> Create Offline Connection Token
                    </h2>
                    <p style="font-size: 14px; color: #7f8c8d; line-height: 1.5; margin-bottom: 20px;">
                        Generate a secure token directly inside this dashboard. You can copy it to configure your local tools immediately, bypassing any cloud authentication servers.
                    </p>
                    
                    <form method="post" action="">
                        <?php wp_nonce_field('connectmwp_generate_token'); ?>
                        <input type="hidden" name="connectmwp_action" value="generate" />
                        
                        <div style="margin-bottom: 20px;">
                            <label for="token_name" style="display: block; font-size: 14px; font-weight: 600; color: #2c3e50; margin-bottom: 8px;">Connection Name</label>
                            <input type="text" name="token_name" id="token_name" value="Claude Desktop" class="regular-text" style="width: 100%; max-width: 400px; padding: 8px 12px; border: 1px solid #ccd0d4; border-radius: 6px; font-size: 14px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.07);" required />
                            <p class="description" style="margin-top: 5px; font-size: 12px; color: #7f8c8d;">E.g. "Claude Desktop", "Cursor - Work Laptop", or "Self Hosting Agent"</p>
                        </div>
                        
                        <button type="submit" class="button button-primary" style="background: #3498db; border-color: #2980b9; box-shadow: 0 2px 4px rgba(52, 152, 219, 0.2); font-weight: 600; font-size: 14px; padding: 4px 20px; height: auto; min-height: 38px; border-radius: 6px;">Generate Token & Instructions</button>
                    </form>
                </div>

                <!-- Card: Active Connections -->
                <div style="background: #fff; border: 1px solid #e1e8ed; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.02);">
                    <h2 style="margin-top: 0; margin-bottom: 15px; font-size: 18px; font-weight: 600; color: #2c3e50; border-bottom: 1px solid #f0f3f4; padding-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span>🛡️</span> Active Connection Tokens
                    </h2>
                    
                    <?php if (empty($all_tokens)): ?>
                        <p style="font-size: 14px; color: #7f8c8d; line-height: 1.5; margin: 10px 0;">No active connections found. Generate a token above to get started.</p>
                    <?php else: ?>
                        <table class="wp-list-table widefat fixed striped" style="border: none; box-shadow: none; margin-top: 10px;">
                            <thead>
                                <tr>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50;">Connection Name</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50;">WordPress User</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50;">Created</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50;">Last Used</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50;">Last IP</th>
                                    <th style="font-weight: 600; padding: 12px 10px; border-bottom: 2px solid #eaeded; color: #2c3e50; text-align: right;">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($all_tokens as $token): ?>
                                    <tr>
                                        <td style="padding: 12px 10px; vertical-align: middle;"><strong><?php echo esc_html($token['name']); ?></strong></td>
                                        <td style="padding: 12px 10px; vertical-align: middle;"><?php echo esc_html($token['user_login']); ?></td>
                                        <td style="padding: 12px 10px; vertical-align: middle; color: #7f8c8d; font-size: 12px;"><?php echo esc_html($token['created']); ?></td>
                                        <td style="padding: 12px 10px; vertical-align: middle; color: #7f8c8d; font-size: 12px;"><?php echo esc_html(!empty($token['last_used']) ? $token['last_used'] : 'Never'); ?></td>
                                        <td style="padding: 12px 10px; vertical-align: middle; font-family: monospace; font-size: 12px; color: #7f8c8d;"><?php echo esc_html(!empty($token['last_ip']) ? $token['last_ip'] : '-'); ?></td>
                                        <td style="padding: 12px 10px; vertical-align: middle; text-align: right;">
                                            <form method="post" style="display:inline;">
                                                <?php wp_nonce_field('connectmwp_revoke_token'); ?>
                                                <input type="hidden" name="connectmwp_action" value="revoke" />
                                                <input type="hidden" name="token_hash" value="<?php echo esc_attr($token['hash']); ?>" />
                                                <button type="submit" class="button button-link-delete" onclick="return confirm('Are you sure you want to revoke this connection?');" style="color: #d63638; border-color: #ccd0d4; padding: 2px 10px; height: auto;">Revoke</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>

                <!-- Card: Public Onboarding -->
                <div style="background: #fff; border: 1px solid #e1e8ed; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.02);">
                    <h2 style="margin-top: 0; margin-bottom: 15px; font-size: 18px; font-weight: 600; color: #2c3e50; border-bottom: 1px solid #f0f3f4; padding-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span>🌐</span> Client Onboarding Gateway
                    </h2>
                    <p style="font-size: 14px; color: #7f8c8d; line-height: 1.5; margin-bottom: 20px;">
                        Connect new AI editors (like Claude desktop or third-party workspaces) dynamically through our centralized setup wizard.
                    </p>
                    <a href="https://connectmwp.com" target="_blank" class="button" style="font-weight: 600; font-size: 14px; padding: 6px 20px; height: auto; min-height: 38px; border-radius: 6px; display: inline-flex; align-items: center; gap: 8px; text-decoration: none; border: 1px solid #ccd0d4; background: #f6f7f7; color: #2c3e50;">
                        <span>🚀</span> Open Onboarding at connectmwp.com
                    </a>
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

    private function revoke_token_globally($hash) {
        $users = get_users([
            'meta_key'     => '_connectmwp_tokens',
            'meta_compare' => 'EXISTS'
        ]);

        foreach ($users as $user) {
            $tokens = get_user_meta($user->ID, '_connectmwp_tokens', true);
            if (is_array($tokens)) {
                $filtered = array_filter($tokens, function($token) use ($hash) {
                    return !hash_equals($token['hash'], $hash);
                });
                update_user_meta($user->ID, '_connectmwp_tokens', array_values($filtered));
            }
        }
    }

    /**
     * Handle OAuth Handshake Authorize Flow
     */
    public function handle_oauth_approve() {
        if (!isset($_GET['page']) || $_GET['page'] !== 'connectmwp-auth') {
            return;
        }

        if (!is_user_logged_in()) {
            auth_redirect();
        }

        // Gate to users with edit_posts capability (H-3 Fix)
        if (!current_user_can('edit_posts')) {
            wp_die('Error: You do not have sufficient privileges to authorize connections.', 'Permission Denied', ['response' => 403]);
        }

        $callback = isset($_GET['callback']) ? esc_url_raw($_GET['callback']) : '';
        $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';

        if (empty($callback)) {
            wp_die('Error: Missing callback URL parameter.', 'Bad Request', ['response' => 400]);
        }

        // Validate callback domain (C-1 Fix)
        if (!$this->is_allowed_callback($callback)) {
            wp_die('Error: Redirection callback domain is not authorized.', 'Authorization Error', ['response' => 400]);
        }

        // Handle Approve POST
        if (isset($_POST['connectmwp_oauth_action'])) {
            check_admin_referer('connectmwp_oauth_approve');
            
            if ($_POST['connectmwp_oauth_action'] === 'approve') {
                $user = wp_get_current_user();
                
                // Generate secure token
                $raw_token = 'connectmwp_tk_' . bin2hex(random_bytes(24));
                $token_hash = hash('sha256', $raw_token);
                
                // Save token metadata to user
                $tokens = get_user_meta($user->ID, '_connectmwp_tokens', true);
                if (!is_array($tokens)) {
                    $tokens = [];
                }
                
                $tokens[] = [
                    'name'      => isset($_POST['app_name']) ? sanitize_text_field($_POST['app_name']) : 'connectMWP Client',
                    'hash'      => $token_hash,
                    'created'   => current_time('mysql'),
                    'last_used' => '',
                    'last_ip'   => '',
                ];
                
                update_user_meta($user->ID, '_connectmwp_tokens', $tokens);
                
                // Redirect back to callback URL with credentials in hash fragment (C-2 Fix)
                $redirect_url = $callback . '#token=' . urlencode($raw_token) . 
                                '&state=' . urlencode($state) . 
                                '&site=' . urlencode(esc_url(home_url()));
                
                wp_safe_redirect($redirect_url);
                exit;
            } else {
                // Denied connection redirects back with error in fragment (C-2 Fix)
                $redirect_url = $callback . '#error=access_denied&state=' . urlencode($state);
                wp_safe_redirect($redirect_url);
                exit;
            }
        }

        // Render clean standalone OAuth approval screen (bypassing wp_iframe to prevent plugin conflicts)
        $this->render_clean_oauth_screen();
        exit;
    }

    public function render_clean_oauth_screen() {
        if (!current_user_can('edit_posts')) {
            wp_die('Error: You do not have sufficient privileges to authorize connections.', 'Permission Denied', ['response' => 403]);
        }

        $callback = isset($_GET['callback']) ? esc_url_raw($_GET['callback']) : '';
        if (!$this->is_allowed_callback($callback)) {
            wp_die('Error: Redirection callback domain is not authorized.', 'Authorization Error', ['response' => 400]);
        }

        $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        $user = wp_get_current_user();
        
        ?>
        <!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo( 'charset' ); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Authorize connectMWP</title>
            <style>
                body {
                    background: #f0f2f5;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                    margin: 0;
                    padding: 20px;
                    box-sizing: border-box;
                }
                .card {
                    max-width: 480px;
                    width: 100%;
                    background: #fff;
                    border: 1px solid #ccd0d4;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.06);
                    border-radius: 8px;
                    padding: 35px;
                    box-sizing: border-box;
                }
                h2 {
                    margin-top: 0;
                    text-align: center;
                    font-size: 24px;
                    color: #1d2327;
                    font-weight: 700;
                }
                p {
                    font-size: 14px;
                    line-height: 1.5;
                    color: #50575e;
                    text-align: center;
                    margin-bottom: 25px;
                }
                .account-info {
                    background: #f0f6fc;
                    padding: 15px;
                    border-left: 4px solid #72aee6;
                    border-radius: 4px;
                    margin-bottom: 30px;
                    font-size: 14px;
                    color: #1d2327;
                }
                label {
                    display: block;
                    font-weight: 600;
                    margin-bottom: 8px;
                    font-size: 14px;
                    color: #1d2327;
                }
                input[type="text"] {
                    width: 100%;
                    padding: 10px 12px;
                    border: 1px solid #8c8f94;
                    border-radius: 6px;
                    box-sizing: border-box;
                    font-size: 14px;
                    background: #fff;
                    color: #2c3338;
                    margin-bottom: 25px;
                    transition: border-color 0.15s ease-in-out;
                }
                input[type="text"]:focus {
                    border-color: #2271b1;
                    outline: none;
                    box-shadow: 0 0 0 1px #2271b1;
                }
                .actions {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .btn {
                    padding: 10px 22px;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.1s ease-in-out;
                    text-decoration: none;
                    box-sizing: border-box;
                }
                .btn-deny {
                    background: #f6f7f7;
                    border: 1px solid #dcdcde;
                    color: #d63638;
                }
                .btn-deny:hover {
                    background: #f0f0f1;
                    border-color: #c3c4c7;
                }
                .btn-approve {
                    background: #2271b1;
                    border: 1px solid #135e96;
                    color: #fff;
                    box-shadow: 0 1px 0 #135e96;
                }
                .btn-approve:hover {
                    background: #135e96;
                    border-color: #0a3d63;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Authorize connectMWP</h2>
                <p>
                    An AI tool is requesting permission to connect to <strong><?php echo esc_html(get_bloginfo('name')); ?></strong>. This will authorize remote commands under your user profile.
                </p>
                
                <div class="account-info">
                    <strong>Connecting Account:</strong> <?php echo esc_html($user->user_login); ?> (<?php echo esc_html($user->user_email); ?>)
                </div>
                
                <form method="post">
                    <?php wp_nonce_field('connectmwp_oauth_approve'); ?>
                    <div>
                        <label for="app_name">Client Name</label>
                        <input type="text" name="app_name" id="app_name" value="Claude Client" required />
                    </div>
                    
                    <div class="actions">
                        <button type="submit" name="connectmwp_oauth_action" value="deny" class="btn btn-deny">Deny</button>
                        <button type="submit" name="connectmwp_oauth_action" value="approve" class="btn btn-approve">Approve & Connect</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        <?php
    }
}

// Instantiate
ConnectMWP_Agent::instance();
