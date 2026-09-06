<?php
// Tests for claude.php.wordpress.access-control.predictable-auth-token-md5-user-id

// md5 of user_id — predictable token, TP.
// ruleid: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$token = md5($user_id);

// sha1 of uid — predictable token, TP.
// ruleid: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$hash = sha1($uid);

// md5 of current_user — predictable, TP.
// ruleid: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$token = md5($current_user);

// sha1 of wp_userid — predictable, TP.
// ruleid: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$hash = sha1($wp_userid);

// md5 of random string — not a user ID variable, safe.
// ok: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$token = md5($random_string);

// wp_generate_password — cryptographically random, safe.
// ok: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$token = wp_generate_password(32, false);

// md5 of email — not a user ID variable, safe.
// ok: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$hash = md5($email_address);

// sha1 of nonce — not a user ID variable, safe.
// ok: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
$hash = sha1($nonce_value);

// Known FP — rate-limit / cache-key derivation: the hash's only consumer is
// get_transient()/set_transient() as the KEY argument, never compared against
// a stored secret. Predictability of a throttle key has no auth impact.
function check_rate_limit( $user_id, $ip_address ) {
    // ok: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
    $cache_key = 'plugin_rate_limit_' . md5( $user_id . $ip_address );
    $request_count = get_transient( $cache_key );
    if ( false === $request_count ) {
        set_transient( $cache_key, 1, MINUTE_IN_SECONDS );
        return true;
    }
    if ( $request_count > 60 ) {
        return false;
    }
    set_transient( $cache_key, $request_count + 1, MINUTE_IN_SECONDS );
    return true;
}

// Same exclusion, sha1 variant.
function check_throttle( $user_id, $ip_address ) {
    // ok: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
    $cache_key = 'plugin_throttle_' . sha1( $user_id . $ip_address );
    $count = get_transient( $cache_key );
    set_transient( $cache_key, (int) $count + 1, MINUTE_IN_SECONDS );
    return true;
}

// A hash derived from a user ID but never consumed by get_transient()/
// set_transient() at all — the exclusion must not suppress this; it remains
// a TP (no cache-key evidence that it's harmless).
function build_magic_link_token( $user_id ) {
    // ruleid: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
    $token = md5( $user_id );
    return add_query_arg( 'auth_token', $token, home_url() );
}

// Known FP — the hashed value is a high-entropy external secret (an API
// access token fetched via get_post_meta() with a token-named key), not
// the small sequential WP user ID this rule targets. Hashing an already-
// unguessable value is unguessable regardless of downstream use.
function clear_account_cache_hash( $post_id ) {
    $user_account_token = get_post_meta( $post_id, '_wpz-insta_token', true ) ?: '';
    if ( ! empty( $user_account_token ) ) {
        // ok: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
        $account_hash = substr( md5( $user_account_token ), 0, 8 );
        delete_transient( 'plugin_configured_' . $post_id . '_acc_' . $account_hash );
    }
}

// Negative control: the source meta key name does NOT signal a token/secret
// (it's a plain cross-reference ID), so the new exclusion must NOT apply —
// this remains a predictable-hash TP.
function tp_hash_from_non_secret_post_meta( $post_id ) {
    $linked_user_id = get_post_meta( $post_id, '_linked_wp_user_id', true );
    // ruleid: claude.php.wordpress.access-control.predictable-auth-token-md5-user-id
    $token = md5( $linked_user_id );
    return add_query_arg( 'auth', $token, home_url() );
}
