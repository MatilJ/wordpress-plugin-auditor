<?php
// Test cases for claude.php.wordpress.idor.cookie-ownership-comparison

// === TRUE POSITIVES — should match ===

// Exact woo-smart-wishlist 6.0.0 pattern: cookie compared to function parameter
// in the unauthenticated else-branch. Both sides are client-controlled.
function tp_woosw_can_edit( $key ) {
    // ruleid: claude.php.wordpress.idor.cookie-ownership-comparison
    if ( is_user_logged_in() ) {
        if ( get_user_meta( get_current_user_id(), 'woosw_key', true ) === $key ) {
            return true;
        }
    } else {
        if ( isset( $_COOKIE['woosw_key'] ) && ( sanitize_text_field( $_COOKIE['woosw_key'] ) === $key ) ) {
            return true;
        }
    }
    return false;
}

// Simpler variant: bare cookie strict-equality check in else branch.
function tp_bare_cookie_session_check( $session_id ) {
    // ruleid: claude.php.wordpress.idor.cookie-ownership-comparison
    if ( is_user_logged_in() ) {
        return current_user_can( 'edit_posts' );
    } else {
        if ( $_COOKIE['guest_session'] === $session_id ) {
            return true;
        }
    }
    return false;
}

// === FALSE POSITIVES — should NOT match ===

// Cookie-based check is NOT inside an is_user_logged_in() else branch.
// The rule only fires when paired with the is_user_logged_in guard.
function ok_cookie_check_without_logged_in_guard( $token ) {
    // ok: claude.php.wordpress.idor.cookie-ownership-comparison
    if ( isset( $_COOKIE['auth_token'] ) && $_COOKIE['auth_token'] === $token ) {
        return true;
    }
    return false;
}

// Cookie is read for display purposes in the else branch (no return true).
// The rule fires only when the cookie check gates a "return true" authorization.
function ok_cookie_display_in_else() {
    if ( is_user_logged_in() ) {
        $name = wp_get_current_user()->display_name;
    } else {
        // ok: claude.php.wordpress.idor.cookie-ownership-comparison
        $name = isset( $_COOKIE['guest_name'] ) ? sanitize_text_field( $_COOKIE['guest_name'] ) : 'Guest';
    }
    return $name;
}
