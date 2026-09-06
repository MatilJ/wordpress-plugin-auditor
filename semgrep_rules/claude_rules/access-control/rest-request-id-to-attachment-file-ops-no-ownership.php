<?php
// Test cases for rest-request-id-to-attachment-file-ops-no-ownership

function rest_replace_no_ownership($request) {
    $params = $request->get_body_params();
    $mediaId = $params['mediaId'];
    // ruleid: claude.php.wordpress.access-control.rest-request-id-to-attachment-file-ops-no-ownership
    $current_file = get_attached_file($mediaId);
    unlink($current_file);
}

function rest_delete_media_no_check($request) {
    $id = $request->get_param('id');
    // ruleid: claude.php.wordpress.access-control.rest-request-id-to-attachment-file-ops-no-ownership
    $file = get_attached_file($id);
    if (file_exists($file)) {
        unlink($file);
    }
}

function rest_replace_with_ownership($request) {
    $params = $request->get_body_params();
    $mediaId = $params['mediaId'];
    if (!current_user_can('edit_post', $mediaId)) {
        return new WP_REST_Response(['error' => 'forbidden'], 403);
    }
    // ok: claude.php.wordpress.access-control.rest-request-id-to-attachment-file-ops-no-ownership
    $current_file = get_attached_file($mediaId);
    unlink($current_file);
}

function rest_delete_with_delete_cap($request) {
    $id = $request->get_param('id');
    if (!current_user_can('delete_post', $id)) {
        return new WP_Error('forbidden', '', array('status' => 403));
    }
    // ok: claude.php.wordpress.access-control.rest-request-id-to-attachment-file-ops-no-ownership
    $file = get_attached_file($id);
    if (file_exists($file)) {
        unlink($file);
    }
}
