<?php
// Test cases for claude.php.wordpress.access.rest-permission-callback-auth-always-true
//
// Rule: functions whose name contains an auth/check verb and whose ENTIRE body
// is only "return true;" — a placeholder permission_callback that was never
// filled with a real capability check.
//
// Confirmed TP source: woo-razorpay 4.8.4 includes/api/auth.php:13-16
//   checkAuthCredentials() { return true; } used as permission_callback for
//   /wp-json/1cc/v1/giftcard/apply (unauthenticated gift card balance enumeration)

// ─── TRUE POSITIVES — should match ──────────────────────────────────────────

// Exact woo-razorpay 4.8.4 pattern: function name contains both 'check' and
// 'auth'; entire body is return true. This missed the existing permission rule
// because the name does not contain 'permission'.
// ruleid: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function checkAuthCredentials()
{
    return true;
}

// Function name contains 'verify' — common REST permission callback naming.
// ruleid: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function verifyAccess()
{
    return true;
}

// Class method variant: name contains 'check', body is only return true.
class MyPlugin {
    // ruleid: claude.php.wordpress.access.rest-permission-callback-auth-always-true
    public function checkTokenCredentials()
    {
        return true;
    }
}

// Single-parameter auth function — still flagged (REST callback can accept 1 WP_REST_Request param).
// ruleid: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function verifyToken( $request )
{
    return true;
}

// ─── FALSE POSITIVES — should NOT match ─────────────────────────────────────

// Real capability check — body is not only "return true;".
// ok: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function checkAuthPermission()
{
    return current_user_can( 'manage_options' );
}

// Conditional logic — body contains more than just return true.
// ok: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function checkUserAccess( $request )
{
    if ( is_user_logged_in() ) {
        return current_user_can( 'edit_posts' );
    }
    return false;
}

// No auth/check verb in the function name — not matched by this rule.
// (Covered by rest-permission-callback-named-always-true if "permission" is present.)
// ok: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function isFeatureEnabled()
{
    return true;
}

// Function body returns false — not a security risk (denies access by default).
// ok: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function checkAuthForAdmin()
{
    return false;
}

// Methods with 2+ parameters — REST permission_callback receives at most 1 argument
// (the WP_REST_Request object); 2-parameter methods are service/validation helpers.
// ok: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function validateCredentials( $token, $businessId )
{
    return true;
}

// ok: claude.php.wordpress.access.rest-permission-callback-auth-always-true
function checkAuthPermissionFor( $userId, $resource, $action )
{
    return true;
}
