<?php

// Test cases for claude.php.wordpress.xss.filename-metadata-unescaped-output

// --- TRUE POSITIVES ---

function display_upload_name_tp1() {
    $filename = $_FILES['upload']['name'];
    // ruleid: claude.php.wordpress.xss.filename-metadata-unescaped-output
    echo '<td>' . $filename . '</td>';
}

function display_basename_tp2($file_path) {
    $name = basename($file_path);
    // ruleid: claude.php.wordpress.xss.filename-metadata-unescaped-output
    echo '<span class="filename">' . $name . '</span>';
}

function display_attachment_meta_tp3($attachment_id) {
    $meta = wp_get_attachment_metadata($attachment_id);
    // ruleid: claude.php.wordpress.xss.filename-metadata-unescaped-output
    echo '<p>File: ' . $meta['file'] . '</p>';
}

function display_attached_file_tp4($attachment_id) {
    $file = get_attached_file($attachment_id);
    // ruleid: claude.php.wordpress.xss.filename-metadata-unescaped-output
    printf('<a href="#">%s</a>', $file);
}

// --- FALSE POSITIVES (properly sanitized) ---

function display_upload_name_escaped_fp1() {
    $filename = $_FILES['upload']['name'];
    // ok: claude.php.wordpress.xss.filename-metadata-unescaped-output
    echo '<td>' . esc_html($filename) . '</td>';
}

function display_basename_sanitized_fp2($file_path) {
    $name = sanitize_file_name(basename($file_path));
    // ok: claude.php.wordpress.xss.filename-metadata-unescaped-output
    echo '<span class="filename">' . $name . '</span>';
}

function display_attachment_meta_escaped_fp3($attachment_id) {
    $meta = wp_get_attachment_metadata($attachment_id);
    // ok: claude.php.wordpress.xss.filename-metadata-unescaped-output
    echo '<p>File: ' . esc_html($meta['file']) . '</p>';
}

function display_upload_name_stripped_fp4() {
    $filename = sanitize_text_field($_FILES['upload']['name']);
    // ok: claude.php.wordpress.xss.filename-metadata-unescaped-output
    echo '<td>' . $filename . '</td>';
}

function display_upload_json_fp5() {
    $filename = $_FILES['upload']['name'];
    // ok: claude.php.wordpress.xss.filename-metadata-unescaped-output
    wp_send_json_success(array('name' => $filename));
}
