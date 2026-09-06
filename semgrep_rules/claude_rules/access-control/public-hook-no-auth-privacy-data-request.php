<?php

// Test cases for claude.php.wordpress.access-control.public-hook-no-auth-privacy-data-request

add_action( 'wp', 'plugin_privacy_form_handler' );
// ruleid: claude.php.wordpress.access-control.public-hook-no-auth-privacy-data-request
function plugin_privacy_form_handler() {
    $params = wp_unslash( $_POST );
    if ( empty( $params['wp-action'] ) || 'wp_privacy_send_request' !== $params['wp-action'] ) {
        return;
    }
    $request_id = wp_create_user_request( $params['email'], 'export_personal_data' );
    wp_send_user_request( $request_id );
}

add_action( 'init', 'plugin_privacy_form_handler_init' );
// ruleid: claude.php.wordpress.access-control.public-hook-no-auth-privacy-data-request
function plugin_privacy_form_handler_init() {
    $email = $_POST['email'];
    wp_create_user_request( $email, 'remove_personal_data' );
}

add_action( 'wp', 'plugin_privacy_form_handler_gated' );
// ok: claude.php.wordpress.access-control.public-hook-no-auth-privacy-data-request
function plugin_privacy_form_handler_gated() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $request_id = wp_create_user_request( $_POST['email'], 'export_personal_data' );
    wp_send_user_request( $request_id );
}

add_action( 'wp', 'plugin_privacy_form_handler_nonce' );
// ok: claude.php.wordpress.access-control.public-hook-no-auth-privacy-data-request
function plugin_privacy_form_handler_nonce() {
    check_admin_referer( 'plugin-privacy-request' );
    wp_create_user_request( $_POST['email'], 'export_personal_data' );
}
