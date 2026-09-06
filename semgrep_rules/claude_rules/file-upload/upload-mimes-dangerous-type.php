<?php

// Test cases for claude.php.wordpress.upload.upload-mimes-dangerous-type

// True positive — expands allowed uploads to a PHP-executable extension.
function allow_phtml_uploads($mimes) {
    // ruleid: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['phtml'] = 'text/html';
    return $mimes;
}

// True positive — SVG upload without any content sanitization signal.
function allow_svg_uploads($mimes) {
    // ruleid: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['svg'] = 'image/svg+xml';
    return $mimes;
}

// False positive — well-established binary raster image formats with no
// browser-side script-execution vector.
function gutenberg_add_heic_upload_mimes($mimes) {
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['heic'] = 'image/heic';
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['heif'] = 'image/heif';
    return $mimes;
}

function allow_webp_uploads($mimes) {
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['webp'] = 'image/webp';
    return $mimes;
}

// False positive — application/octet-stream is the generic "unknown binary"
// type; browsers never execute or MIME-sniff it as HTML/script.
function allow_eps_uploads($mimes) {
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['eps'] = 'application/octet-stream';
    return $mimes;
}

// False positive — Photoshop's proprietary raster format, same no-script-vector
// class as the other binary image formats above.
function allow_psd_uploads($mimes) {
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $mimes['psd'] = 'image/vnd.adobe.photoshop';
    return $mimes;
}

// False positive — WordPress's own 'upload_dir' filter callback: matches the
// function-name regex (contains "upload") and the generic mutate-array-return
// shape, but the keys are directory-path metadata, not MIME-type entries.
function filter_upload_dir($args) {
    $upload_base = trailingslashit($args['basedir']);
    $upload_url  = trailingslashit($args['baseurl']);
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $args['basedir'] = apply_filters('my_plugin_upload_path', $upload_base . 'my-plugin');
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $args['baseurl'] = apply_filters('my_plugin_upload_url', $upload_url . 'my-plugin');
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $args['path'] = $args['basedir'] . $args['subdir'];
    // ok: claude.php.wordpress.upload.upload-mimes-dangerous-type
    $args['url'] = $args['baseurl'] . $args['subdir'];
    return $args;
}

