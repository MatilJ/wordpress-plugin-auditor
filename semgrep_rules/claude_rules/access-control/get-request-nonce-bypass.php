<?php
// Test cases for claude.php.wordpress.access.get-request-nonce-bypass
//
// Rule: auth-named functions that return true unconditionally for non-POST
// HTTP methods after a POST-only nonce/auth check — bypassing authorization
// for GET (and other) requests.
//
// Confirmed TP source: ameliabooking 2.3
//   src/Application/Commands/Command.php:180-203 validateNonce()
//   Checks getMethod() === 'POST' before verifying nonce; returns true for
//   all GET requests, allowing unauthenticated state-changing AJAX calls.

// ─── TRUE POSITIVES — should match ──────────────────────────────────────────

// Exact ameliabooking pattern: validateNonce() with Slim Request object.
// Nonce check exists but only inside the POST branch; GET always returns true.
// ruleid: claude.php.wordpress.access.get-request-nonce-bypass
function validateNonce( $request, $nonce, $action ) {
    if ( $request->getMethod() === 'POST' ) {
        if ( ! wp_verify_nonce( $nonce, $action ) ) {
            throw new \Exception( 'Invalid nonce' );
        }
    }
    return true;
}

// $_SERVER['REQUEST_METHOD'] variant: check_ajax_referer only on POST.
// ruleid: claude.php.wordpress.access.get-request-nonce-bypass
function checkRequestAuth( $request ) {
    if ( strtoupper( $_SERVER['REQUEST_METHOD'] ) === 'POST' ) {
        check_ajax_referer( 'my_action', 'nonce' );
    }
    return true;
}

// ─── FALSE POSITIVES — should NOT match ─────────────────────────────────────

// Capability check is unconditional (outside POST branch) — auth gate is present.
// ok: claude.php.wordpress.access.get-request-nonce-bypass
function validateNonceWithCap( $request ) {
    current_user_can( 'manage_options' );
    if ( $request->getMethod() === 'POST' ) {
        wp_verify_nonce( 'my_nonce', 'my_action' );
    }
    return true;
}

// Function name does not contain an auth/nonce verb — not an auth gate.
// ok: claude.php.wordpress.access.get-request-nonce-bypass
function processFormData( $request ) {
    if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
        sanitize_text_field( $_POST['data'] );
    }
    return true;
}

// KNOWN FP PATTERN (not tested): functions that check `!== 'POST'` for an early
// return still match because `<... "POST" ...>` catches both `=== 'POST'` and
// `!== 'POST'`. The `!== POST` early-return pattern IS secure (non-POST rejected).
// Triage manually: verify the endpoint performs state-changing operations via GET.
// Example:
//   function validateNonceStrict($req) {
//     if ($req->getMethod() !== 'POST') { return false; }  // secure — rejects non-POST
//     wp_verify_nonce(...);
//     return true;
//   }

// No POST check present — different pattern not covered by this rule.
// ok: claude.php.wordpress.access.get-request-nonce-bypass
function checkPermission() {
    return true;
}
