<?php
// claude.php.wordpress.access-control.rest-controller-inconsistent-permissions-cap-tier
//
// Detects permissions_check() that uses has_cap('edit_*') without also requiring
// manage_options — the low-privilege fallback gate that mismatches update_item_permissions_check.
//
// Annotation placement: on the line before the has_cap call inside permissions_check().
// Covers both parameterless form (web-stories pattern) and $request-param form,
// and both guard form (if (!has_cap)) and direct return form.

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// Guard form, no parameter — mirrors web-stories Publisher_Logos_Controller.php:149.
// The if (!has_cap('edit_posts')) guard is the sole capability check.
class Vulnerable_Guard_No_Param_Controller extends WP_REST_Controller {

    private $story_post_type;

    public function permissions_check() {
        // ruleid: claude.php.wordpress.access-control.rest-controller-inconsistent-permissions-cap-tier
        if ( ! $this->story_post_type->has_cap( 'edit_posts' ) ) {
            return new WP_Error( 'rest_forbidden', '', array( 'status' => 403 ) );
        }
        return true;
    }

    public function create_item( $request ) {
        update_option( 'plugin_publisher_logos', array( absint( $request->get_param( 'id' ) ) ) );
        return rest_ensure_response( array() );
    }

    public function update_item_permissions_check( $request ) {
        return current_user_can( 'manage_options' );
    }
}

// Direct return form, single parameter — common WP REST convention.
class Vulnerable_Direct_Return_Controller extends WP_REST_Controller {

    private $post_type_helper;

    public function permissions_check( $request ) {
        // ruleid: claude.php.wordpress.access-control.rest-controller-inconsistent-permissions-cap-tier
        return $this->post_type_helper->has_cap( 'edit_posts' );
    }

    public function create_item( $request ) {
        update_option( 'plugin_publisher_logos', array( absint( $request->get_param( 'id' ) ) ) );
        return rest_ensure_response( array() );
    }

    public function update_item_permissions_check( $request ) {
        return current_user_can( 'manage_options' );
    }
}

// Guard form with CPT-specific capability (edit_web-stories — Contributor level).
class Vulnerable_CPT_Cap_Controller extends WP_REST_Controller {

    private $story_post_type;

    public function permissions_check( $request ) {
        // ruleid: claude.php.wordpress.access-control.rest-controller-inconsistent-permissions-cap-tier
        if ( ! $this->story_post_type->has_cap( 'edit_web-stories' ) ) {
            return new WP_Error( 'rest_forbidden', '', array( 'status' => 403 ) );
        }
        return true;
    }

    public function delete_item( $request ) {
        update_option( 'active_logo', 0 );
        return rest_ensure_response( true );
    }

    public function update_item_permissions_check( $request ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            return new WP_Error( 'rest_forbidden', '', array( 'status' => 403 ) );
        }
        return true;
    }
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// permissions_check also contains a manage_options early-return gate — symmetric,
// excluded by pattern-not-inside.
class Safe_Manage_Options_Gate_Controller extends WP_REST_Controller {

    private $post_type;

    public function permissions_check( $request ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            return false;
        }
        // ok: claude.php.wordpress.access-control.rest-controller-inconsistent-permissions-cap-tier
        return $this->post_type->has_cap( 'edit_posts' );
    }

    public function update_item_permissions_check( $request ) {
        return current_user_can( 'manage_options' );
    }
}

// has_cap('manage_options') — 'manage_options' does not match '^edit_' regex, no fire.
class Safe_High_Cap_Return_Controller extends WP_REST_Controller {

    private $cap_helper;

    public function permissions_check( $request ) {
        // ok: claude.php.wordpress.access-control.rest-controller-inconsistent-permissions-cap-tier
        return $this->cap_helper->has_cap( 'manage_options' );
    }

    public function create_item( $request ) {
        update_option( 'my_plugin_setting', sanitize_key( $request->get_param( 'key' ) ) );
        return rest_ensure_response( array() );
    }
}
