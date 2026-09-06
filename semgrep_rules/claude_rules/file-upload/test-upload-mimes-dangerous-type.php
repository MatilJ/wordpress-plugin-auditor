<?php

// ---- TRUE POSITIVES ----

function set_svg_mimes( $mimes = array() ) {
    // ruleid: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['svg'] = 'image/svg+xml';
    return $mimes;
}

function add_custom_mime_types( $mimes ) {
    // ruleid: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['json'] = 'application/json';
    // ruleid: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['svg']  = 'image/svg+xml';
    return $mimes;
}

function elementor_pack_allow_json_file_upload_mime_types( $mimes ) {
    // ruleid: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['json'] = 'text/plain';
    return $mimes;
}

// ---- FALSE POSITIVES ----

function remove_exe_mime( $mimes ) {
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    unset($mimes['exe']);
    return $mimes;
}

function process_data( $data ) {
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $data['key'] = 'value';
    return $data;
}
