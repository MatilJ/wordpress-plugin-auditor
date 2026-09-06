<?php
// Test file: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// VULNERABLE: $_POST post_id flows to update_post_meta
function vuln_update_meta() {
    check_ajax_referer('meta_nonce', 'nonce');
    $post_id = (int) $_POST['post_id'];
    $value = sanitize_text_field($_POST['value']);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($post_id, '_my_plugin_setting', $value);
    wp_send_json_success();
}

// VULNERABLE: $_REQUEST id flows to delete_post_meta
function vuln_delete_meta() {
    $pid = absint($_REQUEST['id']);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    delete_post_meta($pid, '_thumbnail_id');
}

// VULNERABLE: REST get_param flows to add_post_meta
function vuln_rest_add_meta($request) {
    $post_id = $request->get_param('id');
    $key = sanitize_key($request->get_param('meta_key'));
    $val = $request->get_param('meta_value');
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    add_post_meta($post_id, $key, $val);
}

// VULNERABLE: filter_input flows to update_post_meta
function vuln_filter_meta() {
    $post_id = filter_input(INPUT_POST, 'post_id', FILTER_VALIDATE_INT);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($post_id, '_price', '0.01');
}

// VULNERABLE: REST get_json_params flows to update_post_meta
function vuln_rest_json_meta($request) {
    $params = $request->get_json_params();
    $post_id = $params['post_id'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($post_id, '_status', 'approved');
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: post_id from get_the_ID() — no tainted source
function safe_current_post_meta() {
    $post_id = get_the_ID();
    $value = sanitize_text_field($_POST['value']);
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($post_id, '_my_setting', $value);
}

// SAFE: post_id from DB query — taint broken
function safe_db_meta() {
    global $wpdb;
    $post_id = $wpdb->get_var("SELECT ID FROM {$wpdb->posts} WHERE post_name = 'homepage' LIMIT 1");
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($post_id, '_views', 0);
}

// SAFE: hardcoded post ID
function safe_hardcoded_meta() {
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta(1, '_my_key', 'value');
}

// SAFE: post_id from get_option — taint broken
function safe_option_meta() {
    $page_id = get_option('my_plugin_page_id');
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($page_id, '_setting', 'val');
}

// SAFE: post_id from get_user_meta — taint broken
function safe_user_meta_source() {
    $post_id = get_user_meta(get_current_user_id(), 'assigned_post', true);
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($post_id, '_status', 'active');
}

// SAFE: admin-only gate (manage_options) exceeds per-resource edit_post ownership
function safe_admin_gated_meta() {
    check_ajax_referer('admin_nonce', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error();
    }
    $post_id = sanitize_text_field($_POST['post_id']);
    $enabled = rest_sanitize_boolean(sanitize_text_field($_POST['enabled']));
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    update_post_meta($post_id, '_feature_enabled', $enabled);
}

// SAFE: admin-only gate (manage_options), bare statement form, guards delete
function safe_admin_gated_delete() {
    current_user_can('manage_options');
    $pid = absint($_REQUEST['id']);
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-post-meta-write-no-ownership
    delete_post_meta($pid, '_thumbnail_id');
}
