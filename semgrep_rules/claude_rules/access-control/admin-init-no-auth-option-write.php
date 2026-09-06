<?php

// Test cases for claude.php.wordpress.access.admin-init-no-auth-option-write

add_action( 'admin_init', 'save_widget_title_no_auth' );
// ruleid: claude.php.wordpress.access.admin-init-no-auth-option-write
function save_widget_title_no_auth() {
    $title = $_POST['widget_title'];
    update_option( 'my_plugin_widget_title', $title );
}

add_action( 'admin_init', 'reset_plugin_flag_no_auth' );
// ruleid: claude.php.wordpress.access.admin-init-no-auth-option-write
function reset_plugin_flag_no_auth() {
    $flag = $_GET['reset'];
    if ( $flag ) {
        delete_option( 'my_plugin_flag_' . $flag );
    }
}

add_action( 'admin_init', 'save_widget_title_with_cap_check' );
// ok: claude.php.wordpress.access.admin-init-no-auth-option-write
function save_widget_title_with_cap_check() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $title = $_POST['widget_title'];
    update_option( 'my_plugin_widget_title', $title );
}

// Safe: hardcoded internal self-heal, no request-supplied data reaches the
// write at all — there is nothing for an unauthenticated caller to control.
add_action( 'admin_init', 'ensure_db_version_table_no_input' );
// ok: claude.php.wordpress.access.admin-init-no-auth-option-write
function ensure_db_version_table_no_input() {
    global $wpdb;
    $table = $wpdb->prefix . 'my_plugin_jobs';
    if ( $wpdb->get_var( "SHOW TABLES LIKE '$table'" ) !== $table ) {
        delete_option( 'my_plugin_db_version' );
    }
}

// Request data reaches the write only through a plugin-local wrapper function
// (no raw $_GET/$_POST/$_REQUEST/$_COOKIE token in this function's own body).
add_action( 'admin_init', 'save_onboarding_flag_via_wrapper' );
// ruleid: claude.php.wordpress.access.admin-init-no-auth-option-write
function save_onboarding_flag_via_wrapper() {
    $skip = my_plugin_get_request_var( 'skip' );
    $name = my_plugin_get_request_var( 'option_name' );
    if ( $skip == '1' && ! empty( $name ) ) {
        update_option( 'my_plugin_skip_' . $name, 'yes' );
    }
}

// Safe: the write is additionally gated behind a second boolean sourced from
// a capability-wrapper call (defined elsewhere) before the write — the real
// neutralizer this branch's negative clause recognizes.
add_action( 'admin_init', 'save_onboarding_flag_with_wrapper_capability_check' );
// ok: claude.php.wordpress.access.admin-init-no-auth-option-write
function save_onboarding_flag_with_wrapper_capability_check() {
    $skip = my_plugin_get_request_var( 'skip' );
    $name = my_plugin_get_request_var( 'option_name' );
    if ( $skip == '1' && ! empty( $name ) ) {
        $can_access = My_Plugin_Auth::user_can_access( 'settings' );
        if ( $can_access ) {
            update_option( 'my_plugin_skip_' . $name, 'yes' );
        }
    }
}

// Safe: force-sync a hardcoded default once, gated by checking the SAME
// option's own current value — no request data involved anywhere.
add_action( 'admin_init', 'suppress_upgrade_notice_bar_once' );
// ok: claude.php.wordpress.access.admin-init-no-auth-option-write
function suppress_upgrade_notice_bar_once() {
    $option_key  = '_my_plugin_upgrade_notice_dismissed';
    $future_time = strtotime( '+365 day' );
    $stored      = (int) get_option( $option_key, 0 );
    if ( $stored < strtotime( '+30 day' ) ) {
        update_option( $option_key, $future_time );
    }
}

// Safe: same self-referential shape using the empty()-guard form.
add_action( 'admin_init', 'disable_vendor_notices_once' );
// ok: claude.php.wordpress.access.admin-init-no-auth-option-write
function disable_vendor_notices_once() {
    if ( empty( get_option( 'vendor_onboarded' ) ) ) {
        update_option( 'vendor_onboarded', 1 );
    }
}
