<?php
// Test file for claude.php.wordpress.access-control.wp-update-post-edit-posts-cap-mismatch

// TP 1: Contributor-level capability only; POST-supplied ID via pre-built array variable.
function vulnerable_update_template() {
    check_ajax_referer('my_nonce', 'nonce');
    if (!current_user_can('edit_posts')) {
        wp_send_json_error();
    }
    $post_id = intval($_POST['template_id']);
    $data = ['ID' => $post_id, 'post_status' => 'publish'];
    // ruleid: claude.php.wordpress.access-control.wp-update-post-edit-posts-cap-mismatch
    wp_update_post($data);
    wp_send_json_success();
}

// TP 2: publish_posts only; inline array literal with POST-supplied ID.
function vulnerable_update_page_cpt() {
    check_ajax_referer('page_nonce', 'nonce');
    if (!current_user_can('publish_posts')) {
        wp_send_json_error();
    }
    $id = intval($_POST['post_id']);
    // ruleid: claude.php.wordpress.access-control.wp-update-post-edit-posts-cap-mismatch
    wp_update_post(array('ID' => $id, 'post_status' => 'publish'));
    wp_send_json_success();
}

// FP 1: Per-resource check — current_user_can('edit_post', $id) is sufficient.
function safe_update_with_per_resource_check() {
    check_ajax_referer('safe_nonce', 'nonce');
    $post_id = intval($_POST['template_id']);
    if (!current_user_can('edit_post', $post_id)) {
        wp_send_json_error();
    }
    $data = ['ID' => $post_id, 'post_status' => 'publish'];
    // ok: claude.php.wordpress.access-control.wp-update-post-edit-posts-cap-mismatch
    wp_update_post($data);
    wp_send_json_success();
}

// FP 2: edit_others_pages capability — correct for page-type CPTs.
function safe_update_with_edit_others_pages() {
    check_ajax_referer('safe_nonce', 'nonce');
    if (!current_user_can('edit_others_pages')) {
        wp_send_json_error();
    }
    $post_id = intval($_POST['template_id']);
    // ok: claude.php.wordpress.access-control.wp-update-post-edit-posts-cap-mismatch
    wp_update_post(['ID' => $post_id, 'post_status' => 'publish']);
    wp_send_json_success();
}

// FP 3: Admin gate — PR:H, not in bounty scope.
function safe_update_admin_only() {
    check_ajax_referer('admin_nonce', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error();
    }
    $post_id = intval($_POST['template_id']);
    // ok: claude.php.wordpress.access-control.wp-update-post-edit-posts-cap-mismatch
    wp_update_post(['ID' => $post_id, 'post_status' => 'publish']);
    wp_send_json_success();
}
