<?php
// claude.php.wordpress.access-control.rest-permission-callback-permissive-fallback test cases

// ── Vulnerable patterns (should fire) ────────────────────────────────────────

// Mirrors user-registration v5.1.6 verify_stripe_webhook_signature():
// reads signature header, filters candidates array, returns true when empty —
// bypasses ALL verification when no webhook secret is configured.
// ruleid: claude.php.wordpress.access-control.rest-permission-callback-permissive-fallback
function verify_stripe_webhook_signature( \WP_REST_Request $request ) {
    $stripe_signature = $request->get_header( 'stripe_signature' );
    $body             = $request->get_body();

    $secret_test = get_option( 'plugin_webhook_secret_test', '' );
    $secret_live = get_option( 'plugin_webhook_secret_live', '' );
    $candidates  = array_filter( array( $secret_test, $secret_live ) );

    if ( empty( $candidates ) ) {
        return true; // fails open — no verification performed
    }

    foreach ( $candidates as $secret ) {
        try {
            \Stripe\Webhook::constructEvent( $body, $stripe_signature, $secret );
            return true;
        } catch ( \Exception $e ) {
            continue;
        }
    }
    return false;
}

// Same antipattern with a single legacy secret option.
// ruleid: claude.php.wordpress.access-control.rest-permission-callback-permissive-fallback
function verify_payment_webhook_permission( \WP_REST_Request $request ) {
    $signature = $request->get_header( 'x-signature' );
    $secret    = get_option( 'plugin_payment_secret', '' );

    if ( empty( $secret ) ) {
        return true; // bypass: no HMAC check when secret not configured
    }

    $body     = $request->get_body();
    $expected = hash_hmac( 'sha256', $body, $secret );
    return hash_equals( $expected, $signature );
}

// ── Safe patterns (should NOT fire) ──────────────────────────────────────────

// Returns false when no secret configured — fails closed (correct behaviour).
// ok: claude.php.wordpress.access-control.rest-permission-callback-permissive-fallback
function verify_webhook_strict( \WP_REST_Request $request ) {
    $signature = $request->get_header( 'x-signature' );
    $secret    = get_option( 'plugin_webhook_secret', '' );

    if ( empty( $secret ) ) {
        return false; // strict: deny when not configured
    }

    $body     = $request->get_body();
    $expected = hash_hmac( 'sha256', $body, $secret );
    return hash_equals( $expected, $signature );
}

// Returns WP_Error (403) when no secret configured — fails closed.
// ok: claude.php.wordpress.access-control.rest-permission-callback-permissive-fallback
function verify_webhook_returns_error( \WP_REST_Request $request ) {
    $signature = $request->get_header( 'x-webhook-signature' );
    $secret    = get_option( 'plugin_hook_secret', '' );

    if ( empty( $secret ) ) {
        return new \WP_Error( 'missing_secret', 'Webhook secret not configured.', array( 'status' => 403 ) );
    }

    $body     = $request->get_body();
    $expected = hash_hmac( 'sha256', $body, $secret );
    return hash_equals( $expected, $signature );
}

// Reads header but uses inline hash_hmac + hash_equals — properly verified.
// ok: claude.php.wordpress.access-control.rest-permission-callback-permissive-fallback
function verify_hmac_inline( \WP_REST_Request $request ) {
    $signature = $request->get_header( 'x-signature' );
    $secret    = get_option( 'plugin_secret', '' );
    $body      = $request->get_body();
    $expected  = hash_hmac( 'sha256', $body, $secret );
    return hash_equals( $expected, $signature );
}

// Standard capability-check permission callback — not a webhook gate.
// ok: claude.php.wordpress.access-control.rest-permission-callback-permissive-fallback
function rest_admin_permission() {
    return current_user_can( 'manage_options' );
}
