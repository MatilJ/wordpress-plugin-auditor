<?php
// =============================================================================
// TEST FILE: wp-ajax-nopriv-privileged-role-creation
//
// Detects: wp_ajax_nopriv_ callbacks that assign a custom/privileged role
// Safe:    callbacks that assign 'subscriber', 'customer', or are authenticated
// =============================================================================

// ── VULNERABLE: nopriv callback assigns a custom privileged role ──────────────

// ruleid: wp-ajax-nopriv-privileged-role-creation
function vuln_signup_ajax() {
    $user_id = wp_create_user( 'test', 'pass', 'test@example.com' );
    $user    = new WP_User( $user_id );
    $user->set_role( 'tfhb_host' ); // custom privileged role — any visitor can self-register
    wp_send_json_success();
}

add_action( 'wp_ajax_nopriv_vuln_registration', 'vuln_signup_ajax' );

// ── SAFE: nopriv callback assigns 'subscriber' (standard low-privilege) ──────

// ok: wp-ajax-nopriv-privileged-role-creation
function safe_subscriber_signup() {
    $user_id = wp_create_user( 'test2', 'pass', 'test2@example.com' );
    $user    = new WP_User( $user_id );
    $user->set_role( 'subscriber' ); // safe: low-privilege role appropriate for public registration
    wp_send_json_success();
}

add_action( 'wp_ajax_nopriv_safe_registration', 'safe_subscriber_signup' );

// ── SAFE: nopriv callback assigns 'customer' (WooCommerce low-privilege) ─────

// ok: wp-ajax-nopriv-privileged-role-creation
function safe_customer_signup() {
    $user_id = wp_create_user( 'test3', 'pass', 'test3@example.com' );
    $user    = new WP_User( $user_id );
    $user->set_role( 'customer' ); // safe: standard WooCommerce customer role
    wp_send_json_success();
}

add_action( 'wp_ajax_nopriv_safe_woo_registration', 'safe_customer_signup' );

// ── SAFE: authenticated wp_ajax_ callback assigns a custom role ───────────────
// wp_ajax_ requires the user to be logged in — not a nopriv endpoint.

// ok: wp-ajax-nopriv-privileged-role-creation
function authed_role_assign() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( null, 403 );
    }
    $user_id = intval( $_POST['user_id'] );
    $user    = new WP_User( $user_id );
    $user->set_role( 'shop_manager' ); // admin-gated role assignment — not a nopriv concern
    wp_send_json_success();
}

add_action( 'wp_ajax_admin_promote_user', 'authed_role_assign' );
