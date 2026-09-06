<?php
// Test cases for claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
// Confirmed TP sources: CVE-2025-3102 (OttoKit/SureTriggers), CVE-2024-10781 (CleanTalk)

// === TRUE POSITIVES — get_option() secret compared without empty() guard ===

// Vulnerable: === comparison without empty() check (exact OttoKit pattern)
function verify_api_secret_no_guard( $request ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $secret_key = get_option( 'suretriggers_secret_key' );
    $header_key = $request->get_header( 'Authorization' );
    if ($secret_key === $header_key) {
        return true;
    }
    return false;
}

// Vulnerable: == comparison without empty() check
function verify_api_token_loose( $request ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $api_token = get_option( 'my_plugin_api_token' );
    $provided = sanitize_text_field( $_POST['token'] );
    if ($api_token == $provided) {
        return new WP_REST_Response( 'Authenticated', 200 );
    }
    return new WP_Error( 'unauthorized', 'Invalid token', array( 'status' => 401 ) );
}

// Vulnerable: operands swapped, === comparison, no empty() guard
function verify_license_key_swapped( $request ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $license_key = get_option( 'plugin_license_key' );
    $input_key = sanitize_text_field( $request->get_param( 'license' ) );
    if ($input_key === $license_key) {
        activate_pro_features();
    }
}

// Vulnerable: operands swapped, == comparison, no empty() guard
function verify_auth_password_swapped() {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $stored_password = get_option( 'webhook_auth_password' );
    $submitted = sanitize_text_field( $_SERVER['HTTP_X_AUTH'] );
    if ($submitted == $stored_password) {
        process_webhook();
    }
}

// === FALSE POSITIVES — secret compared WITH empty() guard before comparison ===

// Safe: empty() check before === comparison
function verify_api_secret_with_guard( $request ) {
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $secret_key = get_option( 'suretriggers_secret_key' );
    if (empty($secret_key)) {
        return new WP_Error( 'not_configured', 'Plugin not configured', array( 'status' => 403 ) );
    }
    $header_key = $request->get_header( 'Authorization' );
    if ($secret_key === $header_key) {
        return true;
    }
    return false;
}

// Safe: empty() check before == comparison (swapped operands)
function verify_token_with_empty_check() {
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $api_token = get_option( 'my_plugin_api_token' );
    if (empty($api_token)) {
        wp_die( 'API token not configured' );
    }
    $provided = sanitize_text_field( $_POST['token'] );
    if ($provided == $api_token) {
        return true;
    }
    return false;
}

// Safe: option key does not match secret-related regex
function get_display_name_option() {
    $display_name = get_option( 'my_plugin_display_name' );
    $input = sanitize_text_field( $_POST['name'] );
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ($display_name === $input) {
        return true;
    }
    return false;
}

// === TRUE POSITIVES — hardcoded empty-string literal as the expected value ===
// (variant: fail-closed guard clause, mismatch returns, not a runtime lookup)

// Vulnerable: internal-only dispatch branch hardcodes the expected nonce to ''
// but is reached from a public request handler that re-reads $_GET, so an
// omitted nonce parameter defaults to '' too and the check is a tautology.
function dispatch_action( $args ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( 'internal_run' === $args['run'] ) {
        $expected_nonce = '';
    }
    $args = array_merge( array( 'nonce' => '' ), $args );
    if ( $expected_nonce !== $args['nonce'] ) {
        return;
    }
    start_privileged_job( $args['jobid'] );
}

// Vulnerable: operands swapped, loose comparison, guard clause returns on mismatch
function verify_request_token( $request ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $expected_token = '';
    $submitted = $request->get_param( 'token' );
    if ( $submitted != $expected_token ) {
        return false;
    }
    return process_privileged_request( $request );
}

// Safe: variable name does not match the auth-related regex (plain string
// accumulator, not an expected-credential value)
function build_summary_line( $parts ) {
    $summary = '';
    foreach ( $parts as $part ) {
        $summary .= $part;
    }
    $input = $parts['label'];
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( $summary !== $input ) {
        return;
    }
    return true;
}

// Safe: expected value is a real WP-salted nonce (non-empty, adequate entropy),
// not a hardcoded empty-string literal
function verify_wp_nonce_flow( $args ) {
    $expected_nonce = wp_hash( wp_nonce_tick() . 'my_action', 'nonce' );
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( $expected_nonce !== $args['nonce'] ) {
        return;
    }
    start_privileged_job( $args['jobid'] );
}

// === TRUE POSITIVES — secret read from per-record metadata (not get_option) ===

// Vulnerable: verification key read via an object's own get_meta() accessor,
// compared with === and no emptiness guard (a stored record whose secret meta
// was never written returns '' and matches an attacker-supplied empty value).
function verify_record_submission_key( $record, $submitted_key ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $saved_key = $record->get_meta( 'verification_secret_key', true );
    if ( $submitted_key === $saved_key ) {
        return true;
    }
    return new WP_Error( 'auth_failed', 'No permission', array( 'status' => 401 ) );
}

// Vulnerable: verification token read via get_post_meta(), compared with ===
// and no emptiness guard.
function verify_download_token( $post_id, $submitted_token ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $stored_token = get_post_meta( $post_id, 'download_secret_token', true );
    if ( $stored_token === $submitted_token ) {
        return true;
    }
    return false;
}

// Safe: same object-accessor shape, but the fix combines the emptiness guard
// into the same condition via && before trusting the comparison.
function verify_record_submission_key_fixed( $record, $submitted_key ) {
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $saved_key = $record->get_meta( 'verification_secret_key', true );
    if ( ! empty( $saved_key ) && $submitted_key === $saved_key ) {
        return true;
    }
    return new WP_Error( 'auth_failed', 'No permission', array( 'status' => 401 ) );
}

// Safe: no explicit empty($saved_key) guard, but $submitted_key (the INPUT
// operand) has its own prior !empty() guard in the enclosing condition — an
// empty-by-default $saved_key can never satisfy === against a guaranteed
// non-empty claim value (mirrors a JWT-decoded-claim verification flow).
function verify_jwt_claim_against_order_meta( $decoded, $order ) {
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( ! empty( $decoded->callbackKey ) && ! empty( $decoded->shopOrderId ) ) {
        $saved_key = $order->get_meta( 'verification_secret_key', true );
        if ( $decoded->callbackKey === $saved_key ) {
            return true;
        }
    }
    return false;
}

// Safe: get_post_meta() read whose key does not match the secret-related
// regex — an ordinary stored field, not an authentication credential.
function get_order_review_note( $post_id ) {
    $note = get_post_meta( $post_id, 'customer_review_note', true );
    $input = sanitize_text_field( $_POST['note'] );
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( $note === $input ) {
        return true;
    }
    return false;
}

// === TRUE POSITIVES — secret read via array-key access chained onto
// get_option() (one settings option holding several fields) ===

// Vulnerable: fully inline comparison, no emptiness guard on the array
// element, secret nested under one key of a single options array.
function download_desktop_crit() {
    if ( ! empty( $_GET['apikey'] ) ) {
        $apikey = sanitize_text_field( $_GET['apikey'] );
    } else {
        die();
    }
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( get_option( WPS_IC_OPTIONS )['api_key'] == $apikey ) {
        do_privileged_action();
    }
}

// Vulnerable: indexed value assigned to an intermediate variable first,
// still compared with no preceding empty() guard.
function verify_stored_api_key( $submitted ) {
    // ruleid: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    $stored_key = get_option( 'my_plugin_settings' )['api_key'];
    if ( $stored_key == $submitted ) {
        return true;
    }
    return false;
}

// Safe: inline chain, but the same array element is guarded with !empty()
// inside the same condition before the comparison is trusted.
function download_desktop_crit_fixed() {
    if ( ! empty( $_GET['apikey'] ) ) {
        $apikey = sanitize_text_field( $_GET['apikey'] );
    } else {
        die();
    }
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( ! empty( get_option( WPS_IC_OPTIONS )['api_key'] ) && get_option( WPS_IC_OPTIONS )['api_key'] == $apikey ) {
        do_privileged_action();
    }
}

// Safe: indexed value read into a variable and guarded with !empty() before
// the comparison, mirroring the official fix shape.
function verify_stored_api_key_fixed( $submitted ) {
    $options = get_option( 'my_plugin_settings' );
    $stored_key = $options['api_key'];
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( ! empty( $stored_key ) && $stored_key == $submitted ) {
        return true;
    }
    return false;
}

// Safe: self-sentinel idiom — $tax_items_col_key is compared against the same
// empty-string literal it was initialized to (a "was this ever reassigned"
// discriminator for which of two optional array keys is present), not
// against any externally-influenced operand. The variable name coincidentally
// contains "key" but nothing here is a secret.
function expand_tax_items_column( $columns_list_arr ) {
    $tax_items_col_key = '';
    if ( isset( $columns_list_arr['tax_items'] ) ) {
        $tax_items_col_key = 'tax_items';
    } elseif ( isset( $columns_list_arr['-tax_items'] ) ) {
        $tax_items_col_key = '-tax_items';
    }
    // ok: claude.php.wordpress.access-control.empty-secret-comparison-auth-bypass
    if ( '' !== $tax_items_col_key ) {
        return $columns_list_arr[ $tax_items_col_key ];
    }
    return null;
}
