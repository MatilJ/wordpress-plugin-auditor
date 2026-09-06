<?php

// --- TRUE POSITIVES ---

function import_settings_from_file() {
    $file = $_FILES['import_file']['tmp_name'];
    $data = json_decode(file_get_contents($file), true);
    foreach ($data as $key => $value) {
        // ruleid: claude.php.wordpress.access-control.settings-import-to-option-write
        update_option($key, $value);
    }
    wp_send_json_success();
}

function import_from_request_body($request) {
    $settings = json_decode($request->get_body(), true);
    if (is_array($settings)) {
        foreach ($settings as $option_name => $option_value) {
            // ruleid: claude.php.wordpress.access-control.settings-import-to-option-write
            update_option($option_name, $option_value);
        }
    }
}

function restore_backup() {
    $backup = file_get_contents($_POST['backup_url']);
    $config = json_decode($backup, true);
    // ruleid: claude.php.wordpress.access-control.settings-import-to-option-write
    update_option('plugin_config', $config);
}

// --- FALSE POSITIVES (ok) ---

function import_with_auth() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }
    $file = $_FILES['import_file']['tmp_name'];
    $data = json_decode(file_get_contents($file), true);
    $allowed = array('color_scheme', 'font_size', 'layout');
    foreach ($data as $key => $value) {
        if (in_array($key, $allowed, true)) {
            // ok: claude.php.wordpress.access-control.settings-import-to-option-write
            update_option('mytheme_' . sanitize_key($key), sanitize_text_field($value));
        }
    }
}

function import_with_int_cast() {
    $file = $_FILES['import_file']['tmp_name'];
    $data = json_decode(file_get_contents($file), true);
    // ok: claude.php.wordpress.access-control.settings-import-to-option-write
    update_option('counter', absint($data['counter']));
}

function load_config_from_db() {
    $config = json_decode(get_option('cached_config'), true);
    // todoruleid: claude.php.wordpress.access-control.settings-import-to-option-write
    update_option('active_config', $config);
}

function import_with_full_sanitize() {
    $file = $_FILES['import_file']['tmp_name'];
    $raw = json_decode(file_get_contents($file), true);
    $clean = sanitize_text_field($raw['value']);
    // ok: claude.php.wordpress.access-control.settings-import-to-option-write
    update_option('my_option', $clean);
}

function migrate_hardcoded_default_theme() {
    // Hardcoded literal JSON constant embedded in source — not attacker/import data.
    $default = json_decode('{"modules":{"logo":{"value":""}}}', true);
    // ok: claude.php.wordpress.access-control.settings-import-to-option-write
    update_option('plugin_theme_default', $default, true);
}

function refresh_token_via_cron( $user_id ) {
    // Two-statement form: the outbound HTTP client's own response body is
    // captured into an intermediate variable before decoding — still
    // server-fetched data, not attacker-supplied import/request data.
    $response = wp_remote_get( 'https://api.example.com/refresh' );
    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body );
    // ok: claude.php.wordpress.access-control.settings-import-to-option-write
    update_option( '_plugin_cron_result', array( $user_id => $data->status ) );
}
