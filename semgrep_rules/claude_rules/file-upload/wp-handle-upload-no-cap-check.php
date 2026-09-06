<?php

// ruleid: claude.php.wordpress.upload.wp-handle-upload-no-cap-check
function handle_upload_no_auth() {
    $file = $_FILES['upload'];
    $result = wp_handle_upload($file, ['test_form' => false]);
    wp_send_json_success($result['url']);
}

// ruleid: claude.php.wordpress.upload.wp-handle-upload-no-cap-check
function handle_upload_nonce_only() {
    // nonce-only check is insufficient on nopriv endpoints
    check_ajax_referer('my_action', 'nonce');
    $file = $_FILES['file'];
    $result = wp_handle_upload($file, ['action' => 'my_upload']);
    return $result['url'];
}

// ruleid: claude.php.wordpress.upload.wp-handle-upload-no-cap-check
function handle_upload_logged_in_guard_only() {
    // nonce check inside is_user_logged_in() guard bypassed for anonymous users
    if (is_user_logged_in()) {
        check_ajax_referer('my_action', 'nonce');
    }
    $file = $_FILES['attachment'];
    $result = wp_handle_upload($file, ['action' => 'form_upload']);
    return $result;
}

// ok: claude.php.wordpress.upload.wp-handle-upload-no-cap-check
function handle_upload_with_upload_files_cap() {
    if (!current_user_can('upload_files')) {
        wp_die('Not allowed');
    }
    $file = $_FILES['upload'];
    $result = wp_handle_upload($file, ['test_form' => false]);
    return $result;
}

// ok: claude.php.wordpress.upload.wp-handle-upload-no-cap-check
function admin_import_with_manage_options() {
    if (!current_user_can('manage_options')) {
        wp_die();
    }
    $file = $_FILES['import_file'];
    return wp_handle_upload($file, ['action' => 'import']);
}
