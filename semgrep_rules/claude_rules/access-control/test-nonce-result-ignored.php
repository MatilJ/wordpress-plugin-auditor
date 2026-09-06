<?php
// Test file for nonce-result-ignored + check-ajax-referer-stop-false-ignored rules

// === Tests for wp_verify_nonce ignored ===

function bad_nonce_ignored() {
    // ruleid: claude.php.wordpress.access.nonce-result-ignored
    wp_verify_nonce($_POST['nonce'], 'my_action');
    do_something();
}

function good_nonce_in_if() {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    if (!wp_verify_nonce($_POST['nonce'], 'my_action')) {
        wp_die('Invalid nonce');
    }
    do_something();
}

function good_nonce_assigned() {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    $valid = wp_verify_nonce($_POST['nonce'], 'my_action');
    if (!$valid) wp_die();
}

function good_nonce_returned() {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    return wp_verify_nonce($_POST['nonce'], 'my_action');
}

// === Tests for check_ajax_referer with stop=false ===

function bad_ajax_referer_stop_false() {
    // ruleid: claude.php.wordpress.access.check-ajax-referer-stop-false-ignored
    check_ajax_referer('my_action', 'nonce', false);
    do_something();
}

function good_ajax_referer_stop_false_checked() {
    // ok: claude.php.wordpress.access.check-ajax-referer-stop-false-ignored
    if (!check_ajax_referer('my_action', 'nonce', false)) {
        wp_die('Invalid nonce');
    }
    do_something();
}

function good_ajax_referer_stop_false_assigned() {
    // ok: claude.php.wordpress.access.check-ajax-referer-stop-false-ignored
    $result = check_ajax_referer('my_action', 'nonce', false);
    if (!$result) wp_die();
}
