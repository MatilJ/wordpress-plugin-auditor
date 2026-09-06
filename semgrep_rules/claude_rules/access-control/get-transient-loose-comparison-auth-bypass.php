<?php
// Test cases: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
// Confirmed TP source: post-smtp 2.8.7
//   Postman/Mobile/includes/rest-api/v1/rest-api.php:68
//   $nonce    = get_transient('post_smtp_auth_nonce'); // false when transient absent
//   $auth_key = $request->get_header('auth_key');      // null when header absent
//   if( $auth_key == $nonce ) { ... }                  // null == false → TRUE → auth bypass

// ---- Vulnerable patterns ----

// Vulnerable: stored variable, left-operand form (exact post-smtp pattern)
function connect_app_vulnerable_stored_left( $request ) {
    // ruleid: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
    $nonce    = get_transient( 'my_plugin_auth_nonce' );
    $auth_key = $request->get_header( 'auth_key' );
    if ( $auth_key == $nonce ) {
        update_option( 'my_plugin_device', $auth_key );
        wp_send_json_success();
    }
    wp_send_json_error();
}

// Vulnerable: stored variable, right-operand form
function connect_app_vulnerable_stored_right( $request ) {
    // ruleid: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
    $nonce    = get_transient( 'my_plugin_auth_nonce' );
    $auth_key = $request->get_header( 'auth_key' );
    if ( $nonce == $auth_key ) {
        wp_send_json_success();
    }
    wp_send_json_error();
}

// Vulnerable: inline get_transient() — user input on left
function verify_token_inline_left() {
    $user_key = sanitize_text_field( $_POST['key'] );
    // ruleid: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
    if ( $user_key == get_transient( 'my_plugin_auth_nonce' ) ) {
        return true;
    }
    return false;
}

// Vulnerable: inline get_transient() — user input on right
function verify_token_inline_right() {
    $user_key = sanitize_text_field( $_POST['key'] );
    // ruleid: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
    if ( get_transient( 'my_plugin_auth_nonce' ) == $user_key ) {
        return true;
    }
    return false;
}

// ---- Safe patterns ----

// Safe: strict equality (===) — null !== false, so absent transient cannot bypass
// ok: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
function connect_app_safe_strict( $request ) {
    $nonce    = get_transient( 'my_plugin_auth_nonce' );
    $auth_key = $request->get_header( 'auth_key' );
    if ( $auth_key === $nonce ) {
        wp_send_json_success();
    }
    wp_send_json_error();
}

// Safe: get_transient() used for caching with !== false guard — no == comparison
// ok: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
function get_cached_data( $key ) {
    $cached = get_transient( 'my_plugin_cache_' . $key );
    if ( $cached !== false ) {
        return $cached;
    }
    return null;
}

// Safe: loose comparison against the literal `false` — a plain cache-miss
// check (get_transient()'s own documented "not set" return value), not an
// attacker-influenceable operand. Confirmed FP source: templately 3.7.0
// FullSiteImport::google_font() — cached Google Fonts list refresh check.
// ok: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
function refresh_cached_list_left_literal() {
    $result = get_transient( 'my_plugin_cached_list' );
    if ( false == $result ) {
        $result = fetch_and_cache_list();
    }
    return $result;
}

// Safe: same shape, literal on the right-hand side.
// ok: claude.php.wordpress.access-control.get-transient-loose-comparison-auth-bypass
function refresh_cached_list_right_literal() {
    $result = get_transient( 'my_plugin_cached_list' );
    if ( $result == false ) {
        $result = fetch_and_cache_list();
    }
    return $result;
}
