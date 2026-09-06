<?php

// --- TRUE POSITIVES ---

function enqueue_with_secret_key() {
    $secret = get_option('plugin_api_secret');
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('my-handle', 'MyPlugin', array('key' => $secret));
}

function enqueue_with_stripe_secret() {
    $sk = get_option('stripe_client_secret');
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('payment-js', 'PaymentConfig', array('sk' => $sk));
}

function inline_with_password() {
    $pass = get_option('smtp_password');
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_add_inline_script('admin-js', 'var cfg = ' . json_encode(array('p' => $pass)));
}

function enqueue_with_private_key() {
    $pk = get_option('openai_api_key');
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('ai-handle', 'AiConfig', array('token' => $pk));
}

function enqueue_with_auth_token() {
    $token = get_option('service_auth_token');
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('service-js', 'ServiceConfig', array('t' => $token));
}

function widget_render_echoes_settings_token() {
    $settings = get_widget_settings_for_display();
    $access_token = $settings['exad_facebook_access_token'];
    $query_settings = wp_json_encode(array('access_token' => $access_token, 'widget_id' => 'abc123x'));
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo '<button data-settings="' . esc_attr($query_settings) . '">Load More</button>';
}

function widget_prints_settings_api_key() {
    $settings = get_widget_settings_for_display();
    $api_key = $settings['exad_stripe_api_key'];
    $config = array('key' => $api_key);
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    print wp_json_encode($config);
}

function enqueue_with_credential_getter_static_call() {
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('my-plugin', 'my_data', array(
        'nonce'   => wp_create_nonce('my_nonce'),
        'api_key' => MY_API::getAPIKey(),
    ));
}

function enqueue_with_credential_getter_instance_call() {
    $auth = new Auth_Manager();
    $data = array('token' => $auth->getAuthToken());
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('my-plugin', 'my_data', $data);
}

function echo_plain_function_credential_getter() {
    // ruleid: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo get_app_password();
}

// --- TRUE NEGATIVES ---

function enqueue_with_nonce() {
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('my-handle', 'MyPlugin', array('nonce' => wp_create_nonce('action')));
}

function enqueue_with_site_url() {
    $url = get_option('siteurl');
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('my-handle', 'MyPlugin', array('url' => $url));
}

function enqueue_with_non_secret_option() {
    $color = get_option('plugin_theme_color');
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('theme-js', 'Theme', array('color' => $color));
}

function enqueue_with_non_credential_getter_call() {
    $data = array('display_name' => MY_API::getDisplayName());
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('my-plugin', 'my_data', $data);
}

function fetch_feed_server_side_only() {
    $settings = get_widget_settings_for_display();
    $access_token = $settings['exad_facebook_access_token'];
    $url = "https://graph.facebook.com/posts?access_token={$access_token}";
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    $data = wp_remote_get($url);
    return $data;
}

function print_widget_non_secret_setting() {
    $settings = get_widget_settings_for_display();
    $color = $settings['exad_widget_bg_color'];
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo esc_attr($color);
}

function enqueue_ai_key_presence_flag() {
    $config = array(
        'hasOpenAiKey' => AI_Backend::is_wp() || ! empty( get_option( 'plugin_openai_api_key' ) ),
    );
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('ai-handle', 'AiConfig', $config);
}

function enqueue_google_maps_js_api_key() {
    $google_api_key = get_option('elementor_raven_google_maps_api_key');
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo '<script src="https://maps.googleapis.com/maps/api/js?key=' . esc_js($google_api_key) . '&libraries=places"></script>';
}

function render_password_field_ui_copy($settings, $field) {
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo wp_kses_post($settings['forget_password_text']);
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo esc_html($field['confirm_password_label']);
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo esc_attr($field['confirm_password_placeholder']);
}

function echo_lost_password_page_url() {
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo '<a href="' . esc_url(wpdm_lostpassword_url()) . '">Forgot password?</a>';
}

function echo_lost_password_page_url_method_call() {
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo '<a href="' . esc_url(WPDM()->user->login->lostPasswordURL()) . '">Forgot Password?</a>';
}

function enqueue_oauth_authorize_url_instance_method() {
    $helpers = new Helpers();
    $data = array('authorizeUrl' => $helpers->get_personal_access_token_link());
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    wp_localize_script('my-plugin', 'my_data', $data);
}

function echo_oauth_client_secret_authorize_url_static_call() {
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo Helpers::get_client_secret_auth_link();
}

function echo_password_reset_key_validation_error($login) {
    $user = check_password_reset_key($_GET['key'], $login);
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo esc_html($user->get_error_message());
}

function echo_masked_secret_key_static_call() {
    // Confirmed FP source: advanced-cf7-db 2.1.3 (bundled Freemius SDK)
    // freemius/templates/account.php:517 — FS_Plugin_License::mask_secret_key_for_html()
    // explicitly masks the secret before returning it for display.
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo '<code>' . FS_Plugin_License::mask_secret_key_for_html($install->secret_key) . '</code>';
}

function echo_masked_secret_key_instance_call() {
    // Confirmed FP source: advanced-cf7-db 2.1.3 (bundled Freemius SDK)
    // freemius/templates/account/partials/site.php:265.
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo '<code>' . $license->get_html_escaped_masked_secret_key() . '</code>';
}

function ok_html_template_password_css_class_label() {
    // Guards against a Semgrep PHP-parser artifact on heavily
    // HTML-interspersed .php template files, where $FUNC can bind to a
    // stray HTML/text fragment (e.g. a CSS class name) that happens to
    // contain a credential keyword substring, rather than a real function
    // call.
    ?>
    <span class="js-modal-title js-title-recovery-password"><?php
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    esc_html_e( 'Forgot password', 'my-plugin' ) ?></span>
    <?php
}

function ajax_handler_reuses_settings_bag($feed_data) {
    $settings = get_request_settings();
    $widget_settings = get_widget_settings_for_display();
    $settings['access_token'] = $widget_settings['exad_facebook_access_token'];
    $items = array_splice($feed_data['data'], 0, $settings['post_limit']);
    foreach ($items as $item) {
        // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
        echo esc_html($item['message']);
    }
    // ok: claude.php.wordpress.info-disclosure.localize-script-sensitive-data
    echo esc_html($settings['read_more_text']);
}
