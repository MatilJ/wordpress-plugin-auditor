<?php

// ---- TRUE POSITIVES ----

// TP: nopriv AJAX handler with no auth check — bare call with only POST param check
// ruleid: claude.php.wordpress.upload.media-handle-upload-no-cap-check
function tp_nopriv_upload_no_auth() {
    if ( isset( $_POST['cr_form'] ) && isset( $_POST['cr_item'] ) ) {
        $attachmentId = media_handle_upload( 'cr_file', 0 );
    }
    wp_die();
}

// TP: nonce check present but no current_user_can() — nonce alone is not authorization
// ruleid: claude.php.wordpress.upload.media-handle-upload-no-cap-check
function tp_nonce_only_upload() {
    if ( check_ajax_referer( 'my-upload-nonce', 'nonce', false ) ) {
        $attachmentId = media_handle_upload( 'file', 0 );
    }
    wp_die();
}

// ---- FALSE POSITIVES ----

// OK: current_user_can() gate present in if condition before upload
// ok: claude.php.wordpress.upload.media-handle-upload-no-cap-check
function ok_cap_check_before_upload() {
    if ( ! current_user_can( 'upload_files' ) ) {
        wp_die( -1 );
    }
    $attachmentId = media_handle_upload( 'file', 0 );
    wp_die();
}

// OK: capability check with nonce — properly guarded upload handler
// ok: claude.php.wordpress.upload.media-handle-upload-no-cap-check
function ok_cap_and_nonce_upload() {
    check_ajax_referer( 'my-nonce', 'nonce' );
    if ( ! current_user_can( 'upload_files' ) ) {
        wp_send_json_error( 'Unauthorized' );
    }
    $result = media_handle_upload( 'upload', get_the_ID() );
    wp_die();
}
