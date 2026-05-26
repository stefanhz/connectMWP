<?php
/**
 * Plugin Name: wpConnect Agent
 * Plugin URI: https://connectmwp.com
 * Description: Secure remote connector for connectmwp.com. Exposes safe REST API and Admin-AJAX endpoints signed with client-level tokens.
 * Version: 1.1.0
 * Author: Stefan Heinz, 2morrow.ai
 * Author URI: https://2morrow.ai
 * License: GPLv2
 */

defined('ABSPATH') || exit;

class WPConnect_Agent {

    const OPTION_TOKENS = 'wpconnect_agent_tokens';
    const OPTION_NONCES = 'wpconnect_agent_nonces';
    const API_NAMESPACE = 'wpconnect/v1';

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
        add_action('wp_ajax_wpconnect_api', [$this, 'handle_ajax_request']);
        add_action('wp_ajax_nopriv_wpconnect_api', [$this, 'handle_ajax_request']);

        // Admin pages
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'handle_oauth_approve']);
    }

    /**
     * Authenticate remote requests using the custom X-WPConnect-Auth header
     */
    public function authenticate_request($user_id) {
        if ($user_id) {
            return $user_id;
        }

        $token = $this->get_auth_token_from_header();
        if (empty($token)) {
            return $user_id;
        }

        // Validate replay attack prevention
        if (!$this->validate_replay_headers()) {
            return $user_id;
        }

        // Search for matching token in database
        $token_hash = hash('sha256', $token);
        $user_id_found = $this->find_user_by_token_hash($token_hash);

        if ($user_id_found) {
            $this->update_token_last_used($user_id_found, $token_hash);
            return $user_id_found;
        }

        return $user_id;
    }

    private function get_auth_token_from_header() {
        $custom_auth = '';
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $name => $value) {
                if (strcasecmp($name, 'X-WPConnect-Auth') === 0) {
                    $custom_auth = $value;
                    break;
                }
            }
        }

        if (empty($custom_auth) && isset($_SERVER['HTTP_X_WPCONNECT_AUTH'])) {
            $custom_auth = $_SERVER['HTTP_X_WPCONNECT_AUTH'];
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
                if (strcasecmp($name, 'X-WPConnect-Timestamp') === 0) {
                    $timestamp = $value;
                } elseif (strcasecmp($name, 'X-WPConnect-Nonce') === 0) {
                    $nonce = $value;
                }
            }
        }

        if (empty($timestamp) && isset($_SERVER['HTTP_X_WPCONNECT_TIMESTAMP'])) {
            $timestamp = $_SERVER['HTTP_X_WPCONNECT_TIMESTAMP'];
        }
        if (empty($nonce) && isset($_SERVER['HTTP_X_WPCONNECT_NONCE'])) {
            $nonce = $_SERVER['HTTP_X_WPCONNECT_NONCE'];
        }

        // If either is missing, fail validation
        if (empty($timestamp) || empty($nonce)) {
            return false;
        }

        // Verify timestamp is within 5 minutes (300 seconds)
        if (abs(time() - intval($timestamp)) > 300) {
            return false;
        }

        // Verify nonce hasn't been claimed yet within the window
        $nonces = get_option(self::OPTION_NONCES, []);
        $now = time();

        // Prune expired nonces
        $nonces = array_filter($nonces, function($expiry) use ($now) {
            return $expiry > $now;
        });

        if (isset($nonces[$nonce])) {
            return false; // Replay attack detected
        }

        // Store nonce with a 6-minute expiry window
        $nonces[$nonce] = $now + 360;
        update_option(self::OPTION_NONCES, $nonces, false);

        return true;
    }

    private function find_user_by_token_hash($token_hash) {
        $users = get_users([
            'meta_key'     => '_wpconnect_tokens',
            'meta_compare' => 'EXISTS'
        ]);

        foreach ($users as $user) {
            $tokens = get_user_meta($user->ID, '_wpconnect_tokens', true);
            if (is_array($tokens)) {
                foreach ($tokens as $token) {
                    if (isset($token['hash']) && hash_equals($token['hash'], $token_hash)) {
                        return $user->ID;
                    }
                }
            }
        }

        return false;
    }

    private function update_token_last_used($user_id, $token_hash) {
        $tokens = get_user_meta($user_id, '_wpconnect_tokens', true);
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
                update_user_meta($user_id, '_wpconnect_tokens', $tokens);
            }
        }
    }

    private function get_client_ip() {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
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
        
        $posts_query = new WP_Query([
            'post_type'      => 'post',
            'post_status'    => ['publish', 'draft'],
            'posts_per_page' => $limit,
        ]);

        $posts = [];
        foreach ($posts_query->posts as $post) {
            $posts[] = [
                'id'        => $post->ID,
                'title'     => $post->post_title,
                'url'       => get_permalink($post->ID),
                'status'    => $post->post_status,
                'date'      => $post->post_date,
                'content'   => $post->post_content,
            ];
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

        $post_id = wp_insert_post([
            'post_title'     => $title,
            'post_content'   => $content,
            'post_status'    => $status,
            'post_category'  => $categories,
            'tags_input'     => $tags,
        ]);

        if (is_wp_error($post_id)) {
            return new WP_REST_Response(['success' => false, 'error' => $post_id->get_error_message()], 500);
        }

        if ($featured_media > 0) {
            set_post_thumbnail($post_id, $featured_media);
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
            $post_data['post_status'] = sanitize_key($params['status']);
        }
        if (isset($params['categories'])) {
            $post_data['post_category'] = array_map('intval', (array) $params['categories']);
        }
        if (isset($params['tags'])) {
            $post_data['tags_input'] = array_map('intval', (array) $params['tags']);
        }

        $updated_id = wp_update_post($post_data);
        if (is_wp_error($updated_id)) {
            return new WP_REST_Response(['success' => false, 'error' => $updated_id->get_error_message()], 500);
        }

        if (!empty($params['featured_media'])) {
            set_post_thumbnail($post_id, intval($params['featured_media']));
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

        // Perform the upload
        $attachment_id = media_handle_upload('file', 0); // 0 means unattached

        if (is_wp_error($attachment_id)) {
            return new WP_REST_Response(['success' => false, 'error' => $attachment_id->get_error_message()], 500);
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
        $action = isset($_REQUEST['wpconnect_action']) ? sanitize_key($_REQUEST['wpconnect_action']) : '';
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
            if ($k !== 'action' && $k !== 'wpconnect_action') {
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
            'wpConnect Settings',
            'wpConnect',
            'manage_options',
            'wpconnect',
            [$this, 'render_settings_page']
        );

        // Register the hidden auth page slug so WordPress permits access to it
        add_submenu_page(
            null,
            'Authorize wpConnect',
            'Authorize wpConnect',
            'edit_posts',
            'wpconnect-auth',
            [$this, 'render_oauth_screen']
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }

        // Process revocation
        if (isset($_POST['wpconnect_action']) && $_POST['wpconnect_action'] === 'revoke' && isset($_POST['token_hash'])) {
            check_admin_referer('wpconnect_revoke_token');
            $hash_to_revoke = sanitize_text_field($_POST['token_hash']);
            $this->revoke_token_globally($hash_to_revoke);
            echo '<div class="notice notice-success is-dismissible"><p>Token successfully revoked.</p></div>';
        }

        // Process manual token generation
        $new_token_data = null;
        if (isset($_POST['wpconnect_action']) && $_POST['wpconnect_action'] === 'generate' && isset($_POST['token_name'])) {
            check_admin_referer('wpconnect_generate_token');
            $token_name = sanitize_text_field($_POST['token_name']);
            
            $raw_token = 'wpconnect_tk_' . bin2hex(random_bytes(24));
            $token_hash = hash('sha256', $raw_token);
            
            $user = wp_get_current_user();
            $tokens = get_user_meta($user->ID, '_wpconnect_tokens', true);
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
            
            update_user_meta($user->ID, '_wpconnect_tokens', $tokens);
            
            $new_token_data = [
                'raw_token' => $raw_token,
                'name'      => $token_name,
                'site_url'  => esc_url(home_url())
            ];
        }

        $users = get_users([
            'meta_key'     => '_wpconnect_tokens',
            'meta_compare' => 'EXISTS'
        ]);

        $all_tokens = [];
        foreach ($users as $user) {
            $tokens = get_user_meta($user->ID, '_wpconnect_tokens', true);
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
                    <span style="font-size: 32px;">🔌</span> wpConnect Agent
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
                $claude_cmd = 'claude mcp add wpconnect npx -y wpconnect-mcp --site "' . $site_url . '" --token "' . $raw_token . '"';
                
                $cursor_config = json_encode([
                    'mcpServers' => [
                        'wpconnect' => [
                            'command' => 'npx',
                            'args' => [
                                '-y',
                                'wpconnect-mcp',
                                '--site',
                                $site_url,
                                '--token',
                                $raw_token
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
                        ⚠️ Security Alert: Copy Your Connection Details Now
                    </h3>
                    <p style="font-size: 14px; color: #555; line-height: 1.5; margin-bottom: 20px;">
                        For your security, this raw connection token is stored in the database as a SHA-256 hash. <strong>It cannot be displayed again.</strong> Please copy the configuration below now.
                    </p>
                    
                    <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
                        <div style="font-size: 12px; font-weight: 600; text-transform: uppercase; color: #7f8c8d; margin-bottom: 5px;">Connection Token</div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <code style="font-family: monospace; font-size: 15px; background: #eef1f6; padding: 6px 12px; border-radius: 4px; color: #2c3e50; font-weight: 600; word-break: break-all; width: 100%; border: 1px solid #d5dbdb;"><?php echo esc_html($raw_token); ?></code>
                            <button type="button" class="button" onclick="navigator.clipboard.writeText('<?php echo esc_js($raw_token); ?>').then(() => alert('Token copied!'))" style="white-space: nowrap; height: 35px;">Copy Token</button>
                        </div>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px; display: flex; align-items: center; gap: 5px;">
                            💻 Claude CLI setup command (Claude Code / Desktop)
                        </div>
                        
                        <!-- Interactive Scope Selector -->
                        <div style="margin-bottom: 15px; display: flex; gap: 15px; align-items: center; background: #f8f9fa; padding: 10px 15px; border-radius: 6px; border: 1px solid #e9ecef;">
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

                    <script>
                    function updateClaudeScope(scope) {
                        const siteUrl = "<?php echo esc_js($site_url); ?>";
                        const rawToken = "<?php echo esc_js($raw_token); ?>";
                        let cmd = "claude mcp add ";
                        if (scope === "user") {
                            cmd += "--scope user ";
                        } else if (scope === "project") {
                            cmd += "--scope project ";
                        }
                        cmd += 'wpconnect npx -y wpconnect-mcp --site "' + siteUrl + '" --token "' + rawToken + '"';
                        document.getElementById('claude-cmd-text').value = cmd;
                    }
                    </script>

                    <div>
                        <div style="font-size: 13px; font-weight: 600; color: #2c3e50; margin-bottom: 8px;">
                            🛠️ Cursor IDE / Alternative MCP Client Config (JSON)
                        </div>
                        <div style="position: relative;">
                            <pre style="margin: 0; background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 12px; line-height: 1.4; overflow-x: auto; box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);"><code id="cursor-config-code"><?php echo esc_html($cursor_config); ?></code></pre>
                            <button type="button" class="button" onclick="const code = document.getElementById('cursor-config-code').innerText; navigator.clipboard.writeText(code).then(() => alert('Cursor Config JSON copied!'))" style="position: absolute; top: 10px; right: 10px; background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.2); color: #fff; text-shadow: none;">Copy JSON</button>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; font-size: 13px; color: #31708f; background: #d9edf7; border: 1px solid #bce8f1; border-radius: 6px; padding: 12px; line-height: 1.5; display: flex; align-items: flex-start; gap: 8px;">
                        <span style="font-size: 16px;">💡</span>
                        <div>
                            <strong>Local Development Tip:</strong> Since <code>wpconnect-mcp</code> is not yet published to npm, <code>npx</code> cannot find it. 
                            To run it locally during development, replace <code>npx -y wpconnect-mcp</code> in your command with <code>node /absolute/path/to/wpConnect/wpconnect-mcp/index.js</code> (and ensure you've run <code>npm install</code> in that directory first).
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
                        <?php wp_nonce_field('wpconnect_generate_token'); ?>
                        <input type="hidden" name="wpconnect_action" value="generate" />
                        
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
                                                <?php wp_nonce_field('wpconnect_revoke_token'); ?>
                                                <input type="hidden" name="wpconnect_action" value="revoke" />
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
            'meta_key'     => '_wpconnect_tokens',
            'meta_compare' => 'EXISTS'
        ]);

        foreach ($users as $user) {
            $tokens = get_user_meta($user->ID, '_wpconnect_tokens', true);
            if (is_array($tokens)) {
                $filtered = array_filter($tokens, function($token) use ($hash) {
                    return !hash_equals($token['hash'], $hash);
                });
                update_user_meta($user->ID, '_wpconnect_tokens', array_values($filtered));
            }
        }
    }

    /**
     * Handle OAuth Handshake Authorize Flow
     */
    public function handle_oauth_approve() {
        if (!isset($_GET['page']) || $_GET['page'] !== 'wpconnect-auth') {
            return;
        }

        if (!is_user_logged_in()) {
            auth_redirect();
        }

        $callback = isset($_GET['callback']) ? esc_url_raw($_GET['callback']) : '';
        $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';

        if (empty($callback)) {
            wp_die('Error: Missing callback URL parameter.');
        }

        // Handle Approve POST
        if (isset($_POST['wpconnect_oauth_action'])) {
            check_admin_referer('wpconnect_oauth_approve');
            
            if ($_POST['wpconnect_oauth_action'] === 'approve') {
                $user = wp_get_current_user();
                
                // Generate secure token
                $raw_token = 'wpconnect_tk_' . bin2hex(random_bytes(24));
                $token_hash = hash('sha256', $raw_token);
                
                // Save token metadata to user
                $tokens = get_user_meta($user->ID, '_wpconnect_tokens', true);
                if (!is_array($tokens)) {
                    $tokens = [];
                }
                
                $tokens[] = [
                    'name'      => isset($_POST['app_name']) ? sanitize_text_field($_POST['app_name']) : 'wpConnect Client',
                    'hash'      => $token_hash,
                    'created'   => current_time('mysql'),
                    'last_used' => '',
                    'last_ip'   => '',
                ];
                
                update_user_meta($user->ID, '_wpconnect_tokens', $tokens);
                
                // Redirect back to callback serverless URL with token
                $redirect_url = add_query_arg([
                    'token' => $raw_token,
                    'state' => $state,
                    'site'  => esc_url(home_url())
                ], $callback);
                
                wp_redirect($redirect_url);
                exit;
            } else {
                // Denied connection
                $redirect_url = add_query_arg([
                    'error' => 'access_denied',
                    'state' => $state
                ], $callback);
                wp_redirect($redirect_url);
                exit;
            }
        }

        // Render clean OAuth approval screen using WP admin styles
        wp_iframe([$this, 'render_oauth_screen']);
        exit;
    }

    public function render_oauth_screen() {
        $callback = isset($_GET['callback']) ? esc_url_raw($_GET['callback']) : '';
        $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        $user = wp_get_current_user();
        
        iframe_header();
        ?>
        <div style="max-width:500px; margin: 40px auto; padding: 30px; background:#fff; border:1px solid #ccd0d4; box-shadow:0 1px 3px rgba(0,0,0,.04); border-radius: 4px; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen-Sans,Ubuntu,Cantarell,'Helvetica Neue',sans-serif;">
            <h2 style="margin-top:0; text-align:center; font-size: 24px; color:#23282d;">Authorize wpConnect</h2>
            <p style="font-size:14px; line-height:1.5; color:#50575e; text-align:center; margin-bottom: 25px;">
                An AI tool is requesting permission to connect to <strong><?php echo esc_html(get_bloginfo('name')); ?></strong>. This will authorize remote commands under your user profile.
            </p>
            
            <div style="background:#f0f6fc; padding: 15px; border-left: 4px solid #72aee6; border-radius: 2px; margin-bottom: 30px; font-size:14px;">
                <strong>Connecting Account:</strong> <?php echo esc_html($user->user_login); ?> (<?php echo esc_html($user->user_email); ?>)
            </div>
            
            <form method="post">
                <?php wp_nonce_field('wpconnect_oauth_approve'); ?>
                <div style="margin-bottom: 25px;">
                    <label style="display:block; font-weight:600; margin-bottom: 8px; font-size: 14px; color:#23282d;">Client Name</label>
                    <input type="text" name="app_name" value="Claude Cowork - Stefan's Mac" style="width:100%; padding: 8px; border: 1px solid #8c8f94; border-radius: 4px; box-sizing: border-box; font-size: 14px;" />
                </div>
                
                <div style="display:flex; justify-content: space-between; align-items:center;">
                    <button type="submit" name="wpconnect_oauth_action" value="deny" style="background:#f6f7f7; border: 1px solid #dcdcde; color:#d63638; padding: 10px 20px; border-radius: 4px; cursor:pointer; font-weight: 500; font-size: 14px; transition: 0.1s ease-in-out;">Deny</button>
                    <button type="submit" name="wpconnect_oauth_action" value="approve" style="background:#2271b1; border: none; color:#fff; padding: 10px 25px; border-radius: 4px; cursor:pointer; font-weight: 600; font-size: 14px; box-shadow: 0 1px 0 #135e96; transition: 0.1s ease-in-out;">Approve & Connect</button>
                </div>
            </form>
        </div>
        <?php
        iframe_footer();
    }
}

// Instantiate
WPConnect_Agent::instance();
