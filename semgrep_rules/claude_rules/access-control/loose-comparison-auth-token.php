<?php
// Test cases for claude.php.wordpress.access-control.loose-comparison-auth-token
// Confirmed TP sources: CVE-2024-38770 (WP Time Capsule), CVE-2024-7503

// === TRUE POSITIVES — loose comparison on auth-related variables ===

// Vulnerable: == on auth_token (left operand matches regex)
function verify_auth_token_loose_left( $request ) {
    $auth_token = get_option( 'my_plugin_auth_token' );
    $user_input = sanitize_text_field( $request->get_header( 'X-Auth-Token' ) );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($auth_token == $user_input) { grant_access(); }
}

// Vulnerable: == on secret_key (right operand matches regex)
function verify_secret_key_loose_right( $request ) {
    $provided = sanitize_text_field( $_POST['key'] );
    $secret_key = get_option( 'my_plugin_secret' );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($provided == $secret_key) { grant_access(); }
}

// Vulnerable: != on api_key (left operand matches regex)
function deny_on_key_mismatch( $request ) {
    $api_key = sanitize_text_field( $_GET['api_key'] );
    $stored = get_option( 'stored_api_key' );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($api_key != $stored) { deny(); }
}

// Vulnerable: != on api_secret (right operand matches regex)
function deny_on_secret_mismatch() {
    $input = sanitize_text_field( $_POST['s'] );
    $api_secret = get_option( 'my_api_secret' );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($input != $api_secret) { wp_die( 'Invalid secret' ); }
}

// Vulnerable: == on password variable
function check_password_loose() {
    $password = get_user_meta( $user_id, 'app_password', true );
    $submitted_password = sanitize_text_field( $_POST['pass'] );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($submitted_password == $password) { login_user(); }
}

// Vulnerable: == on hmac variable
function verify_hmac_loose( $payload, $received_hmac ) {
    $expected_hmac = hash_hmac( 'sha256', $payload, SECRET_KEY );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($received_hmac == $expected_hmac) { process_webhook(); }
}

// === FALSE POSITIVES — strict comparison or timing-safe functions ===

// Safe: strict equality (===)
function verify_auth_token_strict( $request ) {
    $auth_token = get_option( 'my_plugin_auth_token' );
    $user_input = sanitize_text_field( $request->get_header( 'X-Auth-Token' ) );
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($auth_token === $user_input) { grant_access(); }
}

// Safe: hash_equals() — timing-safe comparison
function verify_secret_hash_equals() {
    $secret_key = get_option( 'my_plugin_secret' );
    $user_input = sanitize_text_field( $_POST['key'] );
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if (hash_equals($secret_key, $user_input)) { grant_access(); }
}

// Safe: strict inequality (!==)
function deny_strict_inequality() {
    $api_token = get_option( 'api_token' );
    $input = sanitize_text_field( $_GET['token'] );
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($api_token !== $input) { deny(); }
}

// Safe: variable name does not match auth pattern (just a counter)
function check_count() {
    $count = get_option( 'item_count' );
    $expected = 5;
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ($count == $expected) { do_something(); }
}

// Safe: bare $key is a generic loop/array key, not auth-related
function render_tabs( $tabs, $current_tab ) {
    foreach ( $tabs as $key => $label ) {
        // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
        if ( $current_tab == $key ) { echo 'active'; }
    }
}

// Safe: $meta_key is a generic field name, not an auth secret
function check_meta( $fields, $meta_key ) {
    foreach ( $fields as $val ) {
        // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
        if ( $val['name'] == $meta_key ) { process( $val ); }
    }
}

// Safe: null-comparison is a presence/config check, not a secret comparison.
// Confirmed FP source: woo-stripe-payment 4.0.7 class-wc-stripe-gateway.php:88 —
// constructor null-guard on a config param, `if (null != $secret_key)`.
function constructor_null_guard( $secret_key ) {
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( null != $secret_key ) { $this->secret_key = $secret_key; }
}

// Safe: reverse operand order, == against null
function config_present_check( $api_key ) {
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( $api_key == null ) { return; }
}

// Safe: != null on the right-hand auth-named variable
function token_presence_guard( $token ) {
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( null != $token ) { do_something(); }
}

// Safe: != '' is an emptiness/presence check gating whether an outbound API
// call is attempted, not a two-sided comparison against attacker input.
// Confirmed FP source: ultimate-addons-for-contact-form-7 3.5.47
// addons/mailchimp/mailchimp.php — `$api_key != ''` before a Mailchimp ping.
function api_key_presence_guard( $api_key ) {
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( $api_key != '' ) { ping_mailchimp_api( $api_key ); }
}

// Safe: == '' on the right-hand side, auth-named variable on the left
function secret_key_blank_check( $secret_key ) {
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( $secret_key == '' ) { return; }
}

// Safe: != false is an emptiness/presence check, not a secret comparison.
// Confirmed FP source: same mailchimp.php — `$uacf7_mailchimp_api_key != false`.
function api_key_not_false_guard( $uacf7_mailchimp_api_key ) {
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( $uacf7_mailchimp_api_key != false ) { ping_mailchimp_api( $uacf7_mailchimp_api_key ); }
}

// Safe: false == $Y form, auth-named variable on the right
function token_false_check( $token ) {
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( false == $token ) { return; }
}

// === TRUE POSITIVES — comparison nested in a compound condition, camelCase key name ===

// Vulnerable: the loose comparison is one operand of a larger && expression,
// not the sole if-condition — a presence check for the stored value is
// combined with the (still loose) equality check against request input.
function check_frontend_key_compound_condition( $requestUserId ) {
    $storedUserKey = get_user_meta( $requestUserId, 'appLoginUserKey', true );
    $suppliedUserKey = sanitize_text_field( $_POST['userKey'] );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( !empty( $storedUserKey ) && $storedUserKey == $suppliedUserKey ) {
        wp_set_auth_cookie( $requestUserId, true );
    }
}

// Vulnerable: camelCase "...UserKey" naming (no underscore) on the right operand
function verify_user_key_camel_case( $requestUserId ) {
    $suppliedKey = sanitize_text_field( $_POST['key'] );
    $storedUserKey = get_user_meta( $requestUserId, 'sessionUserKey', true );
    // ruleid: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( $suppliedKey == $storedUserKey ) {
        wp_set_auth_cookie( $requestUserId, true );
    }
}

// === FALSE POSITIVES — camelCase key name but safe comparator ===

// Safe: same compound-condition shape, but hash_equals() instead of == — no
// == / != operator is present at all, so the pattern cannot match.
function check_frontend_key_compound_condition_safe( $requestUserId ) {
    $storedUserKey = get_user_meta( $requestUserId, 'appLoginUserKey', true );
    $suppliedUserKey = sanitize_text_field( $_POST['userKey'] );
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( !empty( $storedUserKey ) && hash_equals( (string) $storedUserKey, (string) $suppliedUserKey ) ) {
        wp_set_auth_cookie( $requestUserId, true );
    }
}

// Safe: camelCase key name compared with strict equality (===)
function verify_user_key_camel_case_strict( $requestUserId ) {
    $suppliedKey = sanitize_text_field( $_POST['key'] );
    $storedUserKey = get_user_meta( $requestUserId, 'sessionUserKey', true );
    // ok: claude.php.wordpress.access-control.loose-comparison-auth-token
    if ( $suppliedKey === $storedUserKey ) {
        wp_set_auth_cookie( $requestUserId, true );
    }
}
