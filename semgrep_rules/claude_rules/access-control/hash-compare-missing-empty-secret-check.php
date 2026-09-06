<?php
// Test cases for hash-compare-missing-empty-secret-check

// ---- TRUE POSITIVES: hash comparison with no empty-secret guard ----

function check_site_unlocked_a($mtnc_options) {
    // ruleid: claude.php.wordpress.access-control.hash-compare-missing-empty-secret-check
    if (isset($_COOKIE['site_unlocked']) && $_COOKIE['site_unlocked'] == md5($mtnc_options['site_password'])) {
        return true;
    }
    return false;
}

function check_reset_token($user_secret) {
    // ruleid: claude.php.wordpress.access-control.hash-compare-missing-empty-secret-check
    if ($_GET['token'] == sha1($user_secret)) {
        return true;
    }
    return false;
}

// ---- FALSE POSITIVES (ok): strlen()/!empty() guard present ----

function check_site_locked_guarded($mtnc_options) {
    $site_password = $mtnc_options['site_password'];
    if (strlen($site_password) > 0 && isset($_COOKIE['site_unlocked'])
        // ok: claude.php.wordpress.access-control.hash-compare-missing-empty-secret-check
        && $_COOKIE['site_unlocked'] == md5($site_password)) {
        return true;
    }
    return false;
}

function check_with_empty_guard($secret) {
    if (!empty($secret)
        // ok: claude.php.wordpress.access-control.hash-compare-missing-empty-secret-check
        && $_POST['hash'] == md5($secret)) {
        return true;
    }
    return false;
}
