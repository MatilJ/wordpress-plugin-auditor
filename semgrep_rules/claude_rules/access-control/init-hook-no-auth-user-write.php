<?php

// Test cases for claude.php.wordpress.access-control.init-hook-no-auth-user-write

add_action( 'init', 'activate_license_from_request' );
// ruleid: claude.php.wordpress.access-control.init-hook-no-auth-user-write
function activate_license_from_request() {
    if ( isset( $_GET['activation_response'] ) ) {
        global $current_user;
        $user_id = $current_user->ID;
        $token = sanitize_text_field( $_GET['activation_response'] );
        update_option( 'plugin_license', base64_decode( $token ) );
        update_user_meta( $user_id, 'plugin_user_type', 'advisor' );
        wp_safe_redirect( home_url() );
        exit;
    }
}

add_action( 'wp_loaded', 'promote_user_from_query' );
// ruleid: claude.php.wordpress.access-control.init-hook-no-auth-user-write
function promote_user_from_query() {
    $user_id = get_current_user_id();
    wp_update_user( array( 'ID' => $user_id, 'role' => 'administrator' ) );
}

add_action( 'init', 'activate_license_with_capability_check' );
// ok: claude.php.wordpress.access-control.init-hook-no-auth-user-write
function activate_license_with_capability_check() {
    if ( isset( $_GET['activation_response'] ) && current_user_can( 'manage_options' ) ) {
        global $current_user;
        $user_id = $current_user->ID;
        update_user_meta( $user_id, 'plugin_user_type', 'advisor' );
        wp_safe_redirect( home_url() );
        exit;
    }
}

add_action( 'init', 'activate_license_with_nonce_check' );
// ok: claude.php.wordpress.access-control.init-hook-no-auth-user-write
function activate_license_with_nonce_check() {
    check_admin_referer( 'plugin_license_activation', 'activation_state' );
    global $current_user;
    $user_id = $current_user->ID;
    update_user_meta( $user_id, 'plugin_user_type', 'advisor' );
    wp_safe_redirect( home_url() );
    exit;
}

// ok: claude.php.wordpress.access-control.init-hook-no-auth-user-write
function read_user_type_for_display() {
    $user_id = get_current_user_id();
    return get_user_meta( $user_id, 'plugin_user_type', true );
}
