<?php

// ---- TRUE POSITIVES ----

function tp_remote_get_direct_body() {
    $url = $_POST['url'];
    // ruleid: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $response = wp_remote_get($url);
    $body = wp_remote_retrieve_body($response);
    file_put_contents('/tmp/file.txt', $body);
}

function tp_remote_get_inline_body() {
    $url = get_option('remote_url');
    // ruleid: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $response = wp_remote_get($url);
    file_put_contents($dest, wp_remote_retrieve_body($response));
}

function tp_remote_post_body() {
    // ruleid: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $response = wp_remote_post($api_url, array('body' => $data));
    $body = wp_remote_retrieve_body($response);
    file_put_contents($path, $body);
}

function tp_remote_get_array_access() {
    // ruleid: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $response = wp_remote_get($url);
    file_put_contents($dest, $response['body']);
}

function tp_file_get_contents_url_inline() {
    // ruleid: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    file_put_contents($dest, file_get_contents($img));
}

function tp_file_get_contents_url_intermediate() {
    $img = $listing['photo_url'];
    // ruleid: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $body = file_get_contents($img);
    file_put_contents($dest, $body);
}

// ---- FALSE POSITIVES ----

function ok_remote_get_with_filetype_check() {
    // ok: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $response = wp_remote_get($url);
    $body = wp_remote_retrieve_body($response);
    $filetype = wp_check_filetype($filename);
    if (!$filetype['ext']) { return; }
    file_put_contents($dest, $body);
}

function ok_remote_get_with_ext_check() {
    // ok: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $response = wp_remote_get($url);
    $body = wp_remote_retrieve_body($response);
    $validated = wp_check_filetype_and_ext($tmpfile, $filename);
    if (!$validated['ext']) { return; }
    file_put_contents($dest, $body);
}

function ok_file_get_contents_with_getimagesizefromstring_check() {
    $img = $listing['photo_url'];
    // ok: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $body = file_get_contents($img);
    $info = getimagesizefromstring($body);
    if (!$info) { return; }
    file_put_contents($dest, $body);
}

function ok_file_get_contents_with_filetype_check() {
    $img = $listing['photo_url'];
    // ok: claude.php.wordpress.file-upload.wp-remote-get-to-file-write
    $body = file_get_contents($img);
    $filetype = wp_check_filetype($filename);
    if (!$filetype['ext']) { return; }
    file_put_contents($dest, $body);
}
