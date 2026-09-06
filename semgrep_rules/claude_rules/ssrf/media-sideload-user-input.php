<?php

// Test cases for claude.php.wordpress.ssrf.media-sideload-user-input

function vulnerable_ajax_image_import() {
    $image_url = wp_unslash( $_POST['image_url'] );
    // ruleid: claude.php.wordpress.ssrf.media-sideload-user-input
    $attachment_id = media_sideload_image( $image_url, $post_id );
}

function vulnerable_rest_image_import( $request ) {
    $url = $request->get_param( 'image_url' );
    // ruleid: claude.php.wordpress.ssrf.media-sideload-user-input
    $result = media_sideload_image( $url, 0, null, 'id' );
}

function vulnerable_wp_remote_fopen() {
    $url = $_GET['url'];
    // ruleid: claude.php.wordpress.ssrf.media-sideload-user-input
    $content = wp_remote_fopen( $url );
}

function safe_hardcoded_sideload() {
    // ok: claude.php.wordpress.ssrf.media-sideload-user-input
    $result = media_sideload_image( 'https://cdn.example.com/default.jpg', $post_id );
}

function safe_validated_sideload() {
    $url = wp_http_validate_url( $_POST['image_url'] );
    if ( ! $url ) {
        return;
    }
    // ok: claude.php.wordpress.ssrf.media-sideload-user-input
    $result = media_sideload_image( $url, $post_id );
}

function safe_integer_id_sideload() {
    $id = intval( $_GET['image_id'] );
    // ok: claude.php.wordpress.ssrf.media-sideload-user-input
    $result = media_sideload_image( $id, $post_id );
}

// get_params() returns entire array; taint must propagate through array element access
function vulnerable_rest_get_params_array_access( $request ) {
    $params = $request->get_params();
    $url = isset( $params['image_url'] ) ? esc_url( $params['image_url'] ) : '';
    // ruleid: claude.php.wordpress.ssrf.media-sideload-user-input
    $result = media_sideload_image( $url, 0, null, 'src' );
}
