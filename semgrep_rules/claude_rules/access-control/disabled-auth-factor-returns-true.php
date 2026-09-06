<?php

class Connect_Handshake {

    // Mirrors the real MainWP Child <= 6.1.1 vulnerable shape (CVE-2026-27366):
    // is_verified_register() returned true unconditionally whenever password
    // auth was disabled for the target user, with no fallback secret check.
    public function is_verified_register( $user_name ) {
        // ruleid: claude.php.wordpress.access-control.disabled-auth-factor-returns-true
        if ( ! $this->is_enabled_user_passwd_auth( $user_name ) ) {
            return true;
        }

        $user_pwd = isset( $_POST['userpwd'] ) ? trim( $_POST['userpwd'] ) : '';
        return $this->is_valid_user_pwd( $user_name, $user_pwd );
    }

    public function is_enabled_user_passwd_auth( $user_name ) {
        return (bool) get_user_option( 'enable_passwd_auth_connect', 1 );
    }

    public function is_valid_user_pwd( $user_name, $pwd ) {
        return wp_check_password( $pwd, 'hash', 1 );
    }
}

function is_valid_connection_request( $user ) {
    // ruleid: claude.php.wordpress.access-control.disabled-auth-factor-returns-true
    if ( ! require_signature_check( $user ) ) {
        return true;
    }
    return hash_equals( get_option( 'connection_secret' ), $_POST['signature'] );
}

class Connect_Handshake_Fixed {

    // The actual 6.1.2 patch: the disabled-factor branch now falls back to a
    // password check, a verify token, or a hash_equals()-compared Unique
    // Security ID before ever returning true — never a bare unconditional pass.
    public function is_verified_register( $user_name ) {
        // ok: claude.php.wordpress.access-control.disabled-auth-factor-returns-true
        if ( ! $this->is_enabled_user_passwd_auth( $user_name ) ) {
            $unique_id = $this->get_site_unique_id();
            $posted_id = isset( $_POST['uniqueId'] ) ? $_POST['uniqueId'] : '';

            if ( '' !== $unique_id && hash_equals( $unique_id, $posted_id ) ) {
                return true;
            }

            return false;
        }

        $user_pwd = isset( $_POST['userpwd'] ) ? trim( $_POST['userpwd'] ) : '';
        return $this->is_valid_user_pwd( $user_name, $user_pwd );
    }

    public function is_enabled_user_passwd_auth( $user_name ) {
        return (bool) get_user_option( 'enable_passwd_auth_connect', 1 );
    }

    public function get_site_unique_id() {
        return get_option( 'mainwp_child_uniqueId', '' );
    }

    public function is_valid_user_pwd( $user_name, $pwd ) {
        return wp_check_password( $pwd, 'hash', 1 );
    }
}

// A negated capability/role check is a different, already-covered pattern
// class (missing current_user_can()), not an optional auth-factor toggle.
function get_dashboard_widget( $id ) {
    // ok: claude.php.wordpress.access-control.disabled-auth-factor-returns-true
    if ( ! current_user_can( 'manage_options' ) ) {
        return true;
    }
    return false;
}

// is_plugin_active() is a companion-plugin-presence check gating a
// non-security display mode (preview-only rendering) — env/config data,
// never an admin-configurable auth-factor toggle, despite the "active"
// substring in its name.
function enable_preview_only_mode( $preview_only, $template_type ) {
    if ( $template_type === 'invoice' ) {
        // ok: claude.php.wordpress.access-control.disabled-auth-factor-returns-true
        if ( ! is_plugin_active( 'woocommerce-invoice-addon/woocommerce-invoice-addon.php' ) ) {
            return true;
        }
        return false;
    }
    return $preview_only;
}
