<?php
// Test cases for claude.php.wordpress.upload.media-sideload-no-upload-cap
// Pattern rule: media_sideload_image() / wp_insert_attachment() without upload_files cap check.

// ─── Vulnerable patterns ──────────────────────────────────────────────────────

// media_sideload_image() called without current_user_can('upload_files').
// Handler is gated on 'edit_posts' (Contributor has this), not 'upload_files'.
// ruleid: claude.php.wordpress.upload.media-sideload-no-upload-cap
function upload_url_no_cap( $image_url, $post_id ) {
    // Only checks edit_posts via nonce, not upload_files.
    check_ajax_referer( 'my_nonce', 'nonce' );
    $attachment_id = media_sideload_image( $image_url, $post_id, null, 'id' );
    return $attachment_id;
}

// wp_insert_attachment() called without upload_files check.
// Contributor-accessible handler writes to Media Library.
// ruleid: claude.php.wordpress.upload.media-sideload-no-upload-cap
function upload_bits_no_cap( $data, $filename ) {
    $upload = wp_upload_bits( $filename, null, $data );
    if ( ! $upload['error'] ) {
        $attachment = array(
            'post_title'     => sanitize_file_name( $filename ),
            'post_mime_type' => 'image/png',
            'post_status'    => 'inherit',
        );
        wp_insert_attachment( $attachment, $upload['file'] );
    }
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// media_sideload_image() with upload_files capability check — safe.
// ok: claude.php.wordpress.upload.media-sideload-no-upload-cap
function upload_url_with_cap( $image_url, $post_id ) {
    if ( ! current_user_can( 'upload_files' ) ) {
        return new WP_Error( 'forbidden', 'No permission.' );
    }
    return media_sideload_image( $image_url, $post_id, null, 'id' );
}

// wp_insert_attachment() with upload_files check in conditional — safe.
// ok: claude.php.wordpress.upload.media-sideload-no-upload-cap
function upload_bits_with_cap( $data, $filename ) {
    if ( ! current_user_can( 'upload_files' ) ) {
        wp_send_json_error( 'Permission denied.', 403 );
    }
    $upload = wp_upload_bits( $filename, null, $data );
    if ( ! $upload['error'] ) {
        $attachment = array(
            'post_title'     => sanitize_file_name( $filename ),
            'post_mime_type' => 'image/png',
            'post_status'    => 'inherit',
        );
        wp_insert_attachment( $attachment, $upload['file'] );
    }
}

// media_sideload_image() with manage_options gate — admin-only, out of scope for bounty.
// ok: claude.php.wordpress.upload.media-sideload-no-upload-cap
function import_media_admin_only( $url, $post_id ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Unauthorized' );
    }
    return media_sideload_image( $url, $post_id );
}
