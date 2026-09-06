<?php
// Test cases for claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg

namespace {

// Branch 1: direct superglobal read at the call site.
function check_direct_superglobal( $stored_hash ) {
    // ruleid: claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg
    return wp_check_password( 'some-public-subject', $_GET['bypass'] );
}

function check_direct_superglobal_wrapped( $stored_hash ) {
    // ruleid: claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg
    return wp_check_password( 'some-public-subject', sanitize_text_field( $_POST['token'] ) );
}

// Branch 2: one-hop parameter indirection — real shape confirmed in
// admin-site-enhancements 8.9.1 class-maintenance-mode.php (Finding 1).
// Public caller reads $_GET['bypass'] and passes it straight through to
// this private validator, whose own parameter reaches wp_check_password().
class Maintenance_Mode_Test {
    private function is_bypass_request_valid( $bypass_param ) {
        if ( empty( $bypass_param ) ) {
            return false;
        }
        // ruleid: claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg
        return wp_check_password( site_url(), $bypass_param );
    }

    public function maintenance_mode_redirect() {
        if ( isset( $_GET['bypass'] ) && $this->is_bypass_request_valid( sanitize_text_field( $_GET['bypass'] ) ) ) {
            return;
        }
    }
}

// Branch 3: local variable assigned from a superglobal via the common
// isset-ternary guard, then used as the hash argument. Real shape confirmed
// in admin-site-enhancements 8.9.1 class-password-protection.php (dismissed
// there only because the first argument embeds a genuine secret — see the
// "ok" case below for that distinction).
class Password_Protection_Test {
    public function maybe_show_login_form() {
        $stored_password = 'irrelevant-for-this-branch';
        $auth_cookie = ( isset( $_COOKIE['asenha_password_protection'] ) ? $_COOKIE['asenha_password_protection'] : '' );
        // ruleid: claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg
        if ( true === wp_check_password( $_SERVER['HTTP_HOST'] . '__' . $stored_password, $auth_cookie ) ) {
            return;
        }
    }
}

// FALSE POSITIVE: stored hash is read from user meta (a genuine
// per-installation secret), not from a request superglobal or a
// pass-through parameter/local variable sourced from one. Real shape
// confirmed safe in admin-site-enhancements 8.9.1
// class-view-admin-as-role.php verify_reset_token().
class View_Admin_As_Role_Test {
    public function verify_reset_token( $token, $user_id ) {
        $stored_hash = get_user_meta( $user_id, 'recovery_token_hash', true );
        if ( empty( $stored_hash ) || ! is_string( $stored_hash ) ) {
            return false;
        }
        // ok: claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg
        return wp_check_password( $token, $stored_hash, $user_id );
    }
}

// FALSE POSITIVE: hash is read from the database (WP DB-read pattern), not
// from a request superglobal, a pass-through parameter, or a superglobal
// assigned to a local variable.
function verify_from_db( $subject ) {
    global $wpdb;
    $stored = $wpdb->get_var( $wpdb->prepare( "SELECT hash FROM {$wpdb->prefix}my_table WHERE id = %d", 1 ) );
    // ok: claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg
    return wp_check_password( $subject, $stored );
}

}

namespace ASENHA\Classes {

// Same Branch 2 shape but with the leading-backslash fully-qualified call
// form (\wp_check_password(...)) used by namespaced plugin classes to reach
// a WP Core global-namespace function — the exact call form found in
// admin-site-enhancements 8.9.1 class-maintenance-mode.php itself.
class Maintenance_Mode_Namespaced_Test {
    private function is_bypass_request_valid( $bypass_param ) {
        if ( empty( $bypass_param ) ) {
            return false;
        }
        // ruleid: claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg
        return \wp_check_password( site_url(), $bypass_param );
    }
}

}
