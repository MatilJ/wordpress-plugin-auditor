<?php

// --- TRUE POSITIVES ---

function ajax_debug_info() {
    // ruleid: claude.php.wordpress.info-disclosure.phpinfo-in-handler
    phpinfo();
    wp_die();
}

function rest_system_check() {
    // ruleid: claude.php.wordpress.info-disclosure.phpinfo-in-handler
    phpinfo(INFO_GENERAL);
}

function show_server_info() {
    check_ajax_referer('my_nonce');
    // ruleid: claude.php.wordpress.info-disclosure.phpinfo-in-handler
    phpinfo();
    die();
}

// --- TRUE NEGATIVES ---

function admin_only_phpinfo() {
    if (current_user_can('manage_options')) {
        // ok: claude.php.wordpress.info-disclosure.phpinfo-in-handler
        phpinfo();
    }
}

function admin_combined_check() {
    if (current_user_can('manage_options') && isset($_GET['debug'])) {
        // ok: claude.php.wordpress.info-disclosure.phpinfo-in-handler
        phpinfo();
    }
}

function detect_openssl_version_via_buffer() {
    ob_start();
    // ok: claude.php.wordpress.info-disclosure.phpinfo-in-handler
    @phpinfo();
    $content = ob_get_contents();
    ob_end_clean();
    preg_match_all('#OpenSSL (Header|Library) Version(.*)#im', $content, $matches);
    return $matches;
}

function detect_sigchild_via_buffer() {
    ob_start();
    // ok: claude.php.wordpress.info-disclosure.phpinfo-in-handler
    phpinfo(INFO_GENERAL);
    return false !== strpos(ob_get_clean(), '--enable-sigchild');
}
