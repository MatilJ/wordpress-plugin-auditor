<?php
// Test cases for cookie-flag-bypasses-security-gate

// ---- TRUE POSITIVES: raw cookie flips a security gate, no validation ----

function load_maintenance_page_a() {
    $show_maintenance_page = 1;
    // ruleid: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
    if (!empty($_COOKIE['skip_maintenance_mode'])) {
        $show_maintenance_page = 0;
    }
    return $show_maintenance_page;
}

function check_content_lock() {
    $is_locked = true;
    // ruleid: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
    if (isset($_COOKIE['content_unlock'])) {
        $is_locked = false;
    }
    return $is_locked;
}

function maybe_show_login_form() {
    // ruleid: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
    $auth_cookie = isset( $_COOKIE['site_password_protection'] ) ? $_COOKIE['site_password_protection'] : '';
    if ( 'authenticated' == $auth_cookie ) {
        return;
    }
}

function check_member_area_access() {
    // ruleid: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
    if ( $_COOKIE['member_area_status'] === 'verified' ) {
        return true;
    }
    return false;
}

// ---- FALSE POSITIVES (ok): non-security preference flag ----

function load_theme_pref() {
    $is_dark_theme = false;
    // ok: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
    if (!empty($_COOKIE['dark_mode_pref'])) {
        $is_dark_theme = true;
    }
    return $is_dark_theme;
}

// ---- FALSE POSITIVES (ok): cookie value is actually validated first ----

function check_unlock_with_hash() {
    $show_page = 1;
    if (isset($_COOKIE['unlock']) && hash_equals($expected, $_COOKIE['unlock'])) {
        // ok: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
        $show_page = 0;
    }
    return $show_page;
}

function maybe_show_login_form_fixed() {
    // ok: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
    $auth_cookie = isset( $_COOKIE['site_password_protection'] ) ? $_COOKIE['site_password_protection'] : '';
    if ( wp_check_password( 'random_server_secret_value', $auth_cookie ) ) {
        return;
    }
}

function load_theme_pref_by_value() {
    // ok: claude.php.wordpress.access-control.cookie-flag-bypasses-security-gate
    if ( $_COOKIE['ui_theme'] === 'dark' ) {
        return 'dark-mode';
    }
    return 'light-mode';
}
