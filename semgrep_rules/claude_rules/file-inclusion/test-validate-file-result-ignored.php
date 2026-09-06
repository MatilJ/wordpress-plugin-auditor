<?php
// Test file for validate-file-result-ignored rule

function bad_validate_file_ignored($path) {
    // ruleid: claude.php.wordpress.file.validate-file-result-ignored
    validate_file($path);
    readfile($path);
}

function bad_validate_file_stored_not_checked($path) {
    // ruleid: claude.php.wordpress.file.validate-file-result-ignored
    $valid = validate_file($path);
    file_get_contents($path);
}

function good_validate_file_checked_truthy($path) {
    if (validate_file($path)) {
        wp_die('Invalid');
    }
    // ok: claude.php.wordpress.file.validate-file-result-ignored
    readfile($path);
}

function good_validate_file_checked_strict($path) {
    if (0 !== validate_file($path)) {
        wp_die('Invalid');
    }
    // ok: claude.php.wordpress.file.validate-file-result-ignored
    readfile($path);
}

function good_validate_file_stored_and_checked($path) {
    $ret = validate_file($path);
    if ($ret) {
        return;
    }
    // ok: claude.php.wordpress.file.validate-file-result-ignored
    readfile($path);
}
