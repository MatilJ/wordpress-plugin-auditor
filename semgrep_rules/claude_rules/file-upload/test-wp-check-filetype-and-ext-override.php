<?php

// ---- TRUE POSITIVES ----

function fix_mime_type_svg( $data = null, $file = null, $filename = null, $mimes = null ) {
    $ext = isset( $data['ext'] ) ? $data['ext'] : '';
    if ( $ext === 'svg' ) {
        // ruleid: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
        $data['type'] = 'image/svg+xml';
        // ruleid: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
        $data['ext']  = 'svg';
    }
    return $data;
}

function real_mime_types( $data, $file, $filename, $mimes ) {
    $wp_filetype = wp_check_filetype( $filename, $mimes );
    // ruleid: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
    $data['ext'] = $wp_filetype['ext'];
    // ruleid: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
    $data['type'] = $wp_filetype['type'];
    return $data;
}

function check_filetype_and_ext( $data, $file, $filename, $mimes ) {
    if ( ! $data['type'] ) {
        $filetype = wp_check_filetype( $filename );
        // ruleid: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
        $data['ext'] = $filetype['ext'];
        // ruleid: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
        $data['type'] = $filetype['type'];
    }
    return $data;
}

// ---- FALSE POSITIVES ----

function process_other_data( $data, $file, $filename ) {
    // ok: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
    $data['ext'] = 'txt';
    return $data;
}

function get_download_info( $data ) {
    // ok: claude.php.wordpress.upload.wp-check-filetype-and-ext-override
    $data['type'] = 'download';
    return $data;
}
