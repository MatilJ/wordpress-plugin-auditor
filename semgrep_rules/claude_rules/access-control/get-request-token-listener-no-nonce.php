<?php
// Test cases for claude.php.wordpress.access-control.get-request-token-listener-no-nonce
//
// Confirmed TP source: instagram-feed 6.11.1 (CVE-2026-12002, CWE-352)
//   admin/SBI_oEmbeds.php:306-336 SBI_oEmbeds::maybe_connection_data()
//   Reads $_GET['sbi_access_token'] with no nonce check anywhere in the
//   function, stores it as $return['access_token'], which the caller
//   (statuses_and_info()) persists via update_option('sbi_oembed_token', ...).
//   Fixed in 6.11.2 by adding wp_verify_nonce($_GET['sbi_con'], 'sbi_con')
//   at the top of the same function.

// ─── TRUE POSITIVES — should match ──────────────────────────────────────────

// Near-exact shape of the real CVE: GET-derived token stored under
// 'access_token', no nonce check anywhere in the function.
// ruleid: claude.php.wordpress.access-control.get-request-token-listener-no-nonce
function maybe_connection_data($saved_access_token_data) {
    if (isset($_GET['sbi_access_token'])) {
        $access_token = sanitize_text_field($_GET['sbi_access_token']);
        $return = array();
        if (!empty($access_token) && strlen($access_token) > 20) {
            $return['access_token'] = $access_token;
        }
        return $return;
    }
    return false;
}

// Variant: !empty() guard instead of isset(), generic connector-style name.
// ruleid: claude.php.wordpress.access-control.get-request-token-listener-no-nonce
function maybe_oauth_callback() {
    if (!empty($_GET['fb_oauth_token'])) {
        $token = sanitize_text_field($_GET['fb_oauth_token']);
        $settings = get_option('my_plugin_settings', array());
        $settings['token'] = $token;
        return $settings;
    }
}

// ─── FALSE POSITIVES — should NOT match ─────────────────────────────────────

// Fixed shape: nonce verified before the GET read is trusted.
// ok: claude.php.wordpress.access-control.get-request-token-listener-no-nonce
function maybe_connection_data_fixed($saved_access_token_data) {
    $nonce = !empty($_GET['sbi_con']) ? sanitize_key($_GET['sbi_con']) : '';
    if (!wp_verify_nonce($nonce, 'sbi_con')) {
        return false;
    }
    if (isset($_GET['sbi_access_token'])) {
        $access_token = sanitize_text_field($_GET['sbi_access_token']);
        $return = array();
        $return['access_token'] = $access_token;
        return $return;
    }
    return false;
}

// Fixed via check_admin_referer() instead of wp_verify_nonce() directly.
// ok: claude.php.wordpress.access-control.get-request-token-listener-no-nonce
function connect_callback_with_admin_referer() {
    check_admin_referer('my_connect_action');
    if (isset($_GET['api_token'])) {
        $token = sanitize_text_field($_GET['api_token']);
        $data = array();
        $data['access_token'] = $token;
        return $data;
    }
}

// GET key is not credential/token-shaped — ordinary display parameter.
// ok: claude.php.wordpress.access-control.get-request-token-listener-no-nonce
function render_tab_from_request() {
    if (isset($_GET['active_tab'])) {
        $tab = sanitize_text_field($_GET['active_tab']);
        $data = array();
        $data['selected_tab'] = $tab;
        return $data;
    }
}

// GET-derived value assigned to an array key that is not token/access_token
// shaped — outside this rule's intentionally narrow sink definition.
// ok: claude.php.wordpress.access-control.get-request-token-listener-no-nonce
function store_display_name() {
    if (isset($_GET['auth_token'])) {
        $value = sanitize_text_field($_GET['auth_token']);
        $data = array();
        $data['display_name'] = $value;
        return $data;
    }
}
