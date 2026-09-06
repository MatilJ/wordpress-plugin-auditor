<?php

function validate_upload_1($file) {
    $allowed_extensions = array('.sql', '.gz', '.crypt');
    $found = false;
    foreach ($allowed_extensions as $extension) {
        // ruleid: claude.php.wordpress.upload.strpos-false-coercion-extension-check
        if (strrpos($file->name, $extension) + strlen($extension) === strlen($file->name)) {
            $found = true;
        }
    }
    if (!$found) {
        return false;
    }
    return true;
}

function validate_upload_2($name, $ext) {
    // ruleid: claude.php.wordpress.upload.strpos-false-coercion-extension-check
    if (strpos($name, $ext) + strlen($ext) == strlen($name)) {
        return true;
    }
    return false;
}

function validate_upload_3($name, $ext) {
    // ruleid: claude.php.wordpress.upload.strpos-false-coercion-extension-check
    if (strlen($name) === strrpos($name, $ext) + strlen($ext)) {
        return true;
    }
    return false;
}

function validate_upload_fixed($file) {
    $allowed_extesions = ['sql', 'gz', 'crypt'];
    $file_extension = pathinfo($file->name, PATHINFO_EXTENSION);
    // ok: claude.php.wordpress.upload.strpos-false-coercion-extension-check
    if (!in_array($file_extension, $allowed_extesions)) {
        return false;
    }
    return true;
}

function validate_upload_guarded($name, $ext) {
    // ok: claude.php.wordpress.upload.strpos-false-coercion-extension-check
    if (strrpos($name, $ext) !== false && strrpos($name, $ext) + strlen($ext) === strlen($name)) {
        return true;
    }
    return false;
}

function get_activity_row($wpdb, $type) {
    // ok: claude.php.wordpress.upload.strpos-false-coercion-extension-check
    return $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_activity_log WHERE type = %s AND show_user = 1", $type));
}
