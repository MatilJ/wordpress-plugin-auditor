<?php

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
add_action('wp_ajax_nopriv_save_settings', 'handle_save_settings');
// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
function handle_save_settings() {
    $option = $_POST['option_name'];
    $value = $_POST['option_value'];
    update_option($option, $value);
    wp_send_json_success();
}

// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
add_action('admin_post_nopriv_install_plugin', 'handle_install');
// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
function handle_install() {
    $opt = sanitize_text_field($_POST['option']);
    $val = sanitize_text_field($_POST['opt_value']);
    delete_option($opt);
    add_option($opt, $val);
    wp_die('Done');
}

// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
add_action('wp_ajax_nopriv_update_site_config', array($this, 'update_site_config'));
// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
function update_site_config() {
    $data = $_POST['config'];
    update_site_option('my_site_config', $data);
    wp_send_json_success();
}

// --- FALSE POSITIVES (ok) ---

// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
add_action('wp_ajax_nopriv_save_with_auth', 'handle_save_with_auth');
// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
function handle_save_with_auth() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
        return;
    }
    update_option('my_setting', sanitize_text_field($_POST['value']));
    wp_send_json_success();
}

// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
add_action('wp_ajax_nopriv_save_with_nonce', 'handle_save_with_nonce');
// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
function handle_save_with_nonce() {
    check_ajax_referer('my_nonce_action', 'security');
    update_option('my_option', sanitize_text_field($_POST['value']));
    wp_send_json_success();
}

// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
add_action('wp_ajax_save_admin_only', 'handle_admin_save');
// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
function handle_admin_save() {
    update_option('admin_setting', $_POST['value']);
    wp_send_json_success();
}

// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
add_action('wp_ajax_nopriv_read_only', 'handle_read_only');
// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-option-write
function handle_read_only() {
    $val = get_option('public_counter');
    wp_send_json_success(array('count' => $val));
}
