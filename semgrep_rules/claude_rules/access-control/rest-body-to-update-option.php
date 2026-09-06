<?php
// Tests for claude.php.wordpress.auth.rest-body-to-update-option

// ─── TRUE POSITIVES — should match ───────────────────────────────────────────

// Raw JSON body param stored directly as option (no sanitization at all)
function store_raw_json_param(WP_REST_Request $request) {
    $data = $request->get_json_params();
    // ruleid: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_uid', $data['business_id']);
}

// sanitize_text_field() is NOT in the sanitizer list — passes ' ; ( ) / unchanged,
// making stored value unsafe in JS string context
function store_sanitized_text_field(WP_REST_Request $request) {
    $data   = $request->get_json_params();
    $widget = get_option('my_plugin_settings');
    $widget['uid'] = sanitize_text_field($data['user_data']['business_id']);
    // ruleid: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_settings', $widget);
}

// get_param() variant
function store_via_get_param(WP_REST_Request $request) {
    $name = $request->get_param('business_name');
    // ruleid: claude.php.wordpress.auth.rest-body-to-update-option
    add_option('my_plugin_name', $name);
}

// get_body_params() variant
function store_body_params(WP_REST_Request $request) {
    $params = $request->get_body_params();
    // ruleid: claude.php.wordpress.auth.rest-body-to-update-option
    update_site_option('my_plugin_data', $params['payload']);
}

// ─── FALSE POSITIVES — should NOT match ──────────────────────────────────────

// Integer cast — no XSS characters possible
function store_integer_param(WP_REST_Request $request) {
    $data  = $request->get_json_params();
    $count = intval($data['count']);
    // ok: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_count', $count);
}

// sanitize_key() — alphanumeric / dash / underscore only
function store_key_param(WP_REST_Request $request) {
    $data = $request->get_json_params();
    $key  = sanitize_key($data['option_key']);
    // ok: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_key', $key);
}

// sanitize_email() — RFC 5321 charset excludes JS injection chars
function store_email_param(WP_REST_Request $request) {
    $data  = $request->get_json_params();
    $email = sanitize_email($data['email']);
    // ok: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_email', $email);
}

// wp_kses() — allows only safe HTML, neutralises JS injection
function store_kses_param(WP_REST_Request $request) {
    $data    = $request->get_json_params();
    $content = wp_kses($data['content'], array('b' => array(), 'i' => array()));
    // ok: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_content', $content);
}

// esc_html() — HTML-encodes all special characters
function store_esc_html_param(WP_REST_Request $request) {
    $data  = $request->get_json_params();
    $title = esc_html($data['title']);
    // ok: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_title', $title);
}

// FILTER_VALIDATE_EMAIL — same constraint as sanitize_email()
function store_validated_email(WP_REST_Request $request) {
    $data  = $request->get_json_params();
    $email = filter_var($data['email'], FILTER_VALIDATE_EMAIL);
    // ok: claude.php.wordpress.auth.rest-body-to-update-option
    update_option('my_plugin_email_alt', $email);
}
