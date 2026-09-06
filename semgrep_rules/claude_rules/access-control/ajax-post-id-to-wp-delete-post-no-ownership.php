<?php
// Test file: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// VULNERABLE: $_POST post_id flows to wp_delete_post
function vuln_delete_post() {
    check_ajax_referer('delete_nonce', 'nonce');
    $post_id = (int) $_POST['post_id'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_post($post_id, true);
    wp_send_json_success();
}

// VULNERABLE: $_GET attachment_id flows to wp_delete_attachment
function vuln_delete_attachment() {
    $id = absint($_GET['attachment_id']);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_attachment($id, true);
}

// VULNERABLE: $_REQUEST id flows to wp_trash_post
function vuln_trash_post() {
    $post_id = (int) $_REQUEST['id'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_trash_post($post_id);
}

// VULNERABLE: REST get_param flows to wp_delete_post
function vuln_rest_delete($request) {
    $post_id = $request->get_param('id');
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_post((int) $post_id, true);
}

// VULNERABLE: filter_input flows to wp_delete_attachment
function vuln_filter_delete() {
    $att_id = filter_input(INPUT_POST, 'attachment_id', FILTER_VALIDATE_INT);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_attachment($att_id, true);
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: post_id from DB query — taint broken by server-sourced read
function safe_db_sourced_delete() {
    global $wpdb;
    $id = $wpdb->get_var("SELECT ID FROM {$wpdb->posts} WHERE post_status = 'auto-draft' LIMIT 1");
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_post($id, true);
}

// SAFE: post_id from get_the_ID() — no tainted source
function safe_current_post_delete() {
    $post_id = get_the_ID();
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_post($post_id, true);
}

// SAFE: hardcoded post ID
function safe_hardcoded_delete() {
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_post(42, true);
}

// SAFE: post_id from get_option (DB read breaks taint)
function safe_option_delete() {
    $page_id = get_option('my_plugin_page_id');
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_post($page_id, true);
}

// ── New content deletion sinks ────────────────────────────────────────────────

// VULNERABLE: $_POST comment_id flows to wp_delete_comment
function vuln_delete_comment() {
    $comment_id = (int) $_POST['comment_id'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_comment($comment_id, true);
}

// VULNERABLE: $_POST comment_id flows to wp_trash_comment
function vuln_trash_comment() {
    $comment_id = absint($_REQUEST['id']);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_trash_comment($comment_id);
}

// VULNERABLE: $_POST term_id flows to wp_delete_term
function vuln_delete_term() {
    $term_id = (int) $_POST['term_id'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_term($term_id, 'category');
}

// VULNERABLE: $_POST user_id flows to wp_delete_user
function vuln_delete_user() {
    $user_id = (int) $_POST['user_id'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_user($user_id);
}

// SAFE: hardcoded comment ID
function safe_hardcoded_comment_delete() {
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_comment(99, true);
}

// SAFE: user_id from DB query
function safe_db_user_delete() {
    global $wpdb;
    $user_id = $wpdb->get_var("SELECT ID FROM wp_users WHERE user_login = 'orphaned' LIMIT 1");
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_user($user_id);
}

// SAFE: wp_delete_user($id) guarded by a self-or-broad-capability ownership
// check — only the requester's own account, or a user manager, can be deleted
function safe_guarded_delete_user() {
    $member_id = absint( $_POST['member_id'] );
    if ( absint( $member_id ) === get_current_user_id() || current_user_can( 'edit_users' ) ) {
        // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
        wp_delete_user( absint( $member_id ) );
    }
}

// SAFE: same guard, reversed operand order on both the equality and the ||
function safe_guarded_delete_user_reversed() {
    $member_id = absint( $_POST['member_id'] );
    if ( current_user_can( 'edit_users' ) || get_current_user_id() === absint( $member_id ) ) {
        // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
        wp_delete_user( absint( $member_id ) );
    }
}

// SAFE: wp_delete_attachment($new_attachment_id) guarded by an early-return
// current_user_can('delete_post', $new_attachment_id) check earlier in the
// same method. Confirmed FP source: admin-site-enhancements 8.9.1
// class-media-replacement.php replace_media().
function replace_media( $old_attachment_id ) {
    $new_attachment_id = intval( sanitize_text_field( $_POST['new-attachment-id-' . $old_attachment_id] ) );
    if ( ! current_user_can( 'delete_post', $new_attachment_id ) ) {
        return;
    }
    // ... unrelated file-copy logic in between ...
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-delete-post-no-ownership
    wp_delete_attachment( $new_attachment_id, true );
}
