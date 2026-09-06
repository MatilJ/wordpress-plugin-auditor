<?php
/**
 * Test cases for ajax-post-id-to-wpdb-write-no-ownership.yaml
 * Rule: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
 */

global $wpdb;

// --- TRUE POSITIVES ---

function tp_update_record_by_post_id() {
    global $wpdb;
    check_ajax_referer('my_nonce', 'nonce');
    if (!current_user_can('edit_posts')) { wp_die(); }
    $record_id = (int) $_POST['record_id'];
    $new_date = sanitize_text_field($_POST['new_date']);
    $wpdb->update(
        $wpdb->prefix . 'custom_posts',
        array('sched_date' => $new_date),
        // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
        array('id' => $record_id)
    );
    wp_send_json_success();
}

function tp_delete_record_by_post_id() {
    global $wpdb;
    check_ajax_referer('my_nonce', 'nonce');
    if (!current_user_can('edit_posts')) { wp_die(); }
    $record_id = (int) $_POST['id'];
    $wpdb->delete(
        $wpdb->prefix . 'custom_posts',
        // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
        array('id' => $record_id)
    );
    wp_send_json_success();
}

function tp_query_update_by_post_id() {
    global $wpdb;
    check_ajax_referer('my_nonce', 'nonce');
    if (!current_user_can('edit_posts')) { wp_die(); }
    $record_id = (int) $_POST['b2s_id'];
    $new_date = sanitize_text_field($_POST['date']);
    $wpdb->query($wpdb->prepare(
        "UPDATE {$wpdb->prefix}custom_posts SET sched_date = %s WHERE id = %d",
        // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
        $new_date,
        // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
        $record_id
    ));
    wp_send_json_success();
}

// --- FALSE POSITIVES (should NOT match) ---

function fp_update_with_ownership_check() {
    global $wpdb;
    check_ajax_referer('my_nonce', 'nonce');
    if (!current_user_can('edit_posts')) { wp_die(); }
    $record_id = (int) $_POST['record_id'];
    $row = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}custom_posts WHERE id = %d AND user_id = %d",
        $record_id, get_current_user_id()
    ));
    if (!$row) { wp_send_json_error(); return; }
    $wpdb->update(
        $wpdb->prefix . 'custom_posts',
        array('sched_date' => sanitize_text_field($_POST['date'])),
        // ok: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
        array('id' => $row->id)
    );
    wp_send_json_success();
}

function fp_id_from_db_not_user_input() {
    global $wpdb;
    check_ajax_referer('my_nonce', 'nonce');
    $record_id = $wpdb->get_var("SELECT id FROM {$wpdb->prefix}custom_posts WHERE user_id = " . get_current_user_id());
    $wpdb->update(
        $wpdb->prefix . 'custom_posts',
        array('status' => 'done'),
        // ok: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
        array('id' => $record_id)
    );
    wp_send_json_success();
}

function fp_option_value_not_user_input() {
    global $wpdb;
    $setting = get_option('my_plugin_target_id');
    $wpdb->delete(
        $wpdb->prefix . 'custom_posts',
        // ok: claude.php.wordpress.access-control.ajax-post-id-to-wpdb-write-no-ownership
        array('id' => $setting)
    );
}
