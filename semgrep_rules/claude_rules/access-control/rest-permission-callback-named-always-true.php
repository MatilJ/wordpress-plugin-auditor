<?php
// Test cases for claude.php.wordpress.access.rest-permission-callback-named-always-true

class TestRestRoutes {

    // === TRUE POSITIVES — should match ===

    // Class method: permission_check in name, body is only return true
    // ruleid: claude.php.wordpress.access.rest-permission-callback-named-always-true
    public function view_logic_type_results_permission_check()
    {
        return true;
    }

    // === FALSE POSITIVES — should NOT match ===

    // Permission function that performs a real capability check — safe
    // ok: claude.php.wordpress.access.rest-permission-callback-named-always-true
    public function manage_settings_permission_check()
    {
        return current_user_can( 'manage_options' );
    }

    // Permission function checking edit_posts — safe
    // ok: claude.php.wordpress.access.rest-permission-callback-named-always-true
    public function edit_surveys_permission_check( $request )
    {
        return current_user_can( 'edit_posts' );
    }

    // Permission function with conditional logic — safe (not unconditional return true)
    // ok: claude.php.wordpress.access.rest-permission-callback-named-always-true
    public function view_public_data_permission_check()
    {
        if ( is_user_logged_in() ) {
            return current_user_can( 'read' );
        }
        return false;
    }
}

// === TRUE POSITIVES — standalone function ===

// Standalone function with permission in name, body is only return true
// ruleid: claude.php.wordpress.access.rest-permission-callback-named-always-true
function survey_results_permission_check()
{
    return true;
}

// === FALSE POSITIVES — standalone ===

// Non-permission function that returns true — name does not match regex
// ok: claude.php.wordpress.access.rest-permission-callback-named-always-true
function is_feature_enabled()
{
    return true;
}
