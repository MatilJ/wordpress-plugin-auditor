<?php
// Test file: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// VULNERABLE: $_POST post_id flows to delete_post_meta
function vuln_delete_post_meta() {
    check_ajax_referer('meta_nonce', 'nonce');
    $post_id = (int) $_POST['post_id'];
    // ruleid: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_post_meta($post_id, '_custom_field');
}

// VULNERABLE: $_POST comment_id flows to delete_comment_meta
function vuln_delete_comment_meta() {
    $comment_id = absint($_POST['comment_id']);
    // ruleid: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_comment_meta($comment_id, 'rating');
}

// VULNERABLE: $_POST user_id flows to delete_user_meta
function vuln_delete_user_meta() {
    $user_id = (int) $_POST['user_id'];
    // ruleid: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_user_meta($user_id, 'profile_picture');
}

// VULNERABLE: $_GET term_id flows to delete_term_meta
function vuln_delete_term_meta() {
    $term_id = absint($_GET['term_id']);
    // ruleid: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_term_meta($term_id, 'icon_url');
}

// VULNERABLE: REST param flows to delete_metadata
function vuln_rest_delete_meta($request) {
    $object_id = $request->get_param('id');
    // ruleid: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_metadata('post', $object_id, '_plugin_data');
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: hardcoded post ID
function safe_hardcoded_meta_delete() {
    // ok: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_post_meta(42, '_transient_data');
}

// SAFE: post_id from DB query (taint broken)
function safe_db_sourced_meta_delete() {
    global $wpdb;
    $post_id = $wpdb->get_var("SELECT ID FROM wp_posts WHERE post_type = 'temp' LIMIT 1");
    // ok: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_post_meta($post_id, '_temporary_flag');
}

// SAFE: user_id from get_option (taint broken)
function safe_option_user_meta_delete() {
    $user_id = get_option('plugin_owner_id');
    // ok: claude.php.wordpress.access-control.user-input-to-delete-metadata-no-ownership
    delete_user_meta($user_id, 'old_setting');
}
