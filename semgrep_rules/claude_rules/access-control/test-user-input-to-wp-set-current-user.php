<?php

// ---- TRUE POSITIVES ----

function tp_direct_post_id() {
    $id = $_POST['user_id'];
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user($id);
}

function tp_get_id() {
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user($_GET['uid']);
}

function tp_cookie_id() {
    $uid = $_COOKIE['litespeed_role'];
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user($uid);
}

function tp_rest_param_id($request) {
    $id = $request->get_param('simulate_user');
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user($id);
}

function tp_intval_not_sanitizer() {
    $id = intval($_POST['user_id']);
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user($id);
}

// ---- FALSE POSITIVES ----

function ok_current_user_id() {
    $id = get_current_user_id();
    // ok: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user($id);
}

function ok_hardcoded_id() {
    // ok: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user(0);
}

function ok_validated_cookie() {
    $id = wp_validate_auth_cookie();
    // ok: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user($id);
}

// Auto-login after self-registration: $result is the ID of the account this
// same request just created via wc_create_new_customer(), not an
// attacker-chosen existing user ID. Confirmed FP: woo-stripe-payment 4.0.7
// CartCheckout::create_customer().
function ok_auto_login_after_self_registration( $email ) {
    $result = wc_create_new_customer( $email, $email, wp_generate_password() );
    // ok: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user( $result );
}

function ok_auto_login_after_wp_insert_user( $userdata ) {
    $user_id = wp_insert_user( $userdata );
    // ok: claude.php.wordpress.access.user-input-to-wp-set-current-user
    wp_set_current_user( $user_id );
}
