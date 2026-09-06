<?php
// Test cases for claude.php.wordpress.access-control.wp-authenticate-app-password-unchecked
// Confirmed TP sources: CVE-2026-8181 (Burst Statistics), CVE-2025-27007 (OttoKit)

// === TRUE POSITIVES — wp_authenticate_application_password() without is_wp_error() ===

// Vulnerable: uses $user->ID without checking for WP_Error
// ruleid: claude.php.wordpress.access-control.wp-authenticate-app-password-unchecked
function handle_api_request_no_check( $request ) {
    $username = sanitize_text_field( $request->get_param( 'username' ) );
    $app_pass = sanitize_text_field( $request->get_param( 'password' ) );
    $user = wp_authenticate_application_password( null, $username, $app_pass );
    $data = get_user_meta( $user->ID, 'private_data', true );
    return new WP_REST_Response( $data, 200 );
}

// Vulnerable: sets auth cookie from unchecked result
// ruleid: claude.php.wordpress.access-control.wp-authenticate-app-password-unchecked
function auto_login_app_password( $request ) {
    $login = sanitize_text_field( $request->get_param( 'login' ) );
    $pass  = sanitize_text_field( $request->get_param( 'app_password' ) );
    $user = wp_authenticate_application_password( null, $login, $pass );
    wp_set_current_user( $user->ID );
    wp_set_auth_cookie( $user->ID, true );
    return new WP_REST_Response( array( 'success' => true ), 200 );
}

// === FALSE POSITIVES — proper error checking after authentication ===

// Safe: is_wp_error() check immediately after authentication
// ok: claude.php.wordpress.access-control.wp-authenticate-app-password-unchecked
function handle_api_request_with_check( $request ) {
    $username = sanitize_text_field( $request->get_param( 'username' ) );
    $app_pass = sanitize_text_field( $request->get_param( 'password' ) );
    $user = wp_authenticate_application_password( null, $username, $app_pass );
    if ( is_wp_error( $user ) ) {
        return new WP_Error( 'auth_failed', 'Authentication failed', array( 'status' => 401 ) );
    }
    $data = get_user_meta( $user->ID, 'private_data', true );
    return new WP_REST_Response( $data, 200 );
}

// Safe: instanceof WP_User check
// ok: claude.php.wordpress.access-control.wp-authenticate-app-password-unchecked
function handle_api_request_instanceof( $request ) {
    $username = sanitize_text_field( $request->get_param( 'username' ) );
    $app_pass = sanitize_text_field( $request->get_param( 'password' ) );
    $user = wp_authenticate_application_password( null, $username, $app_pass );
    if ( ! ( $user instanceof WP_User ) ) {
        return new WP_Error( 'auth_failed', 'Invalid credentials', array( 'status' => 401 ) );
    }
    return new WP_REST_Response( array( 'user_id' => $user->ID ), 200 );
}
