<?php

// ---- TRUE POSITIVES ----

function tp_direct_post_uid() {
    $uid = $_POST['user_id'];
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-password
    wp_set_password($_POST['new_pass'], $uid);
}

function tp_get_uid() {
    $user_id = $_GET['uid'];
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-password
    wp_set_password('newpassword123', $user_id);
}

function tp_rest_param_uid($request) {
    $user_id = $request->get_param('user_id');
    $password = $request->get_param('password');
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-password
    wp_set_password($password, $user_id);
}

function tp_intval_not_sanitizer() {
    $uid = intval($_POST['user_id']);
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-password
    wp_set_password($_POST['pass'], $uid);
}

// ---- FALSE POSITIVES ----

function ok_current_user() {
    $uid = get_current_user_id();
    // ok: claude.php.wordpress.access.user-input-to-wp-set-password
    wp_set_password($_POST['new_pass'], $uid);
}

function ok_hardcoded_uid() {
    // ok: claude.php.wordpress.access.user-input-to-wp-set-password
    wp_set_password('randompass', 1);
}
