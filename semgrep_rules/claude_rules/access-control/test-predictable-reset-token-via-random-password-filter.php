<?php

// ---- TRUE POSITIVES ----

// Real CVE-2025-14975 shape: OOP callback registered via array($this, 'method'),
// unconditionally overwrites the "random" value from raw $_POST data.
class TP_Oop_Class {

    public function __construct() {
        add_filter( 'random_password', array( $this, 'logincust_set_password' ) );
    }

    public function logincust_set_password( $password ) {

        if ( ! empty( $_POST['user_pass'] ) ) {
            // ruleid: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
            $password = $_POST['user_pass'];
        }

        return $password;
    }
}

// Procedural variant: string callback name, unconditional overwrite, wp_unslash() wrapper.
add_filter( 'random_password', 'my_plugin_set_password' );

function my_plugin_set_password( $password ) {
    // ruleid: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
    $password = wp_unslash( $_POST['user_pass'] );
    return $password;
}

// Inline closure variant, sanitized but still directly request-controlled.
add_filter( 'random_password', function ( $password ) {
    if ( isset( $_REQUEST['new_password'] ) ) {
        // ruleid: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
        $password = sanitize_text_field( $_REQUEST['new_password'] );
    }
    return $password;
} );

// ---- FALSE POSITIVES ----

// Official 2.5.4 patch shape: password is set via wp_set_password() bound to the
// register_new_user action's own $user_id argument. random_password is never
// hooked at all, so this cannot poison get_password_reset_key().
class OK_Patched_Class {

    public function __construct() {
        add_action( 'register_new_user', array( $this, 'update_default_password_nag' ) );
    }

    public function update_default_password_nag( $user_id ) {

        update_user_meta( $user_id, 'default_password_nag', false );

        if ( isset( $_POST['user_pass'] ) && ! empty( $_POST['user_pass'] ) ) {
            // ok: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
            $password = sanitize_text_field( wp_unslash( $_POST['user_pass'] ) );
            wp_set_password( $password, $user_id );
        }
    }
}

// random_password hooked only to tweak complexity — never reads request data.
add_filter( 'random_password', 'my_plugin_lengthen_password' );

function my_plugin_lengthen_password( $password ) {
    // ok: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
    $password = $password . wp_generate_password( 4, false );
    return $password;
}

// random_password hooked with a capability check gating the override.
class OK_Capability_Gated {

    public function __construct() {
        add_filter( 'random_password', array( $this, 'maybe_override' ) );
    }

    public function maybe_override( $password ) {
        if ( current_user_can( 'manage_options' ) ) {
            if ( ! empty( $_POST['user_pass'] ) ) {
                // ok: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
                $password = $_POST['user_pass'];
            }
        }
        return $password;
    }
}

// ---- NEW TRUE POSITIVES (CVE-2026-1994 shape: s2member) ----

// Hook registration lives in a completely different file (common in larger
// OOP plugins: a centralized hooks.php referencing 'Class::method' strings),
// so no add_filter() call is visible in this file at all. The callback is
// recognized purely by its conventional name, and the override is reached
// through an arbitrary same-class wrapper call rather than a direct
// sanitizer, and the gate only checks a generic URL substring -- not the
// specific WP core action in play (e.g. it fires during password reset too).
class TP_Centralized_Hooks_Class {

    public static function maybe_custom_pass( $password ) {
        return trim( stripslashes( (string) $password ) );
    }

    public static function generate_password( $password = '' ) {

        if ( ! is_admin() && preg_match( '/\/wp-login\.php/i', $_SERVER['REQUEST_URI'] ) ) {
            if ( ! empty( $_POST['custom_reg_field_user_pass1'] ) ) {
                // ruleid: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
                $password = self::maybe_custom_pass( $_POST['custom_reg_field_user_pass1'] );
            }
        }
        return $password;
    }
}

// ---- NEW FALSE POSITIVES ----

// Official CVE-2026-1994 fix shape: the callback bails out immediately
// whenever WP core's own password-reset-flow actions have fired, before any
// request-controlled override logic can run.
class OK_DidAction_Guarded_Class {

    public static function maybe_custom_pass( $password ) {
        return trim( stripslashes( (string) $password ) );
    }

    public static function generate_password( $password = '' ) {

        if ( did_action( 'retrieve_password' ) || did_action( 'login_form_rp' ) || did_action( 'login_form_resetpass' ) )
            return $password;

        if ( ! is_admin() && preg_match( '/\/wp-login\.php/i', $_SERVER['REQUEST_URI'] ) ) {
            if ( ! empty( $_POST['custom_reg_field_user_pass1'] ) ) {
                // ok: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
                $password = self::maybe_custom_pass( $_POST['custom_reg_field_user_pass1'] );
            }
        }
        return $password;
    }
}

// A same-named-convention function that never reads request data at all --
// should not be flagged regardless of the naming-based context match.
function random_password_lengthener( $password ) {
    // ok: claude.php.wordpress.access-control.predictable-reset-token-via-random-password-filter
    $password = $password . wp_generate_password( 4, false );
    return $password;
}
