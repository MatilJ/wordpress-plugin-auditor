<?php
/**
 * Test cases for
 * claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
 *
 * Rule catches: a function that creates (wp_create_user()/wp_insert_user()) or
 * promotes (wp_update_user()) a WordPress account and assigns it a non-default
 * role (set_role() / the 'role' array key, excluding 'subscriber'/'customer'),
 * with no current_user_can() call anywhere in the enclosing function.
 *
 * Motivating real-world TP: hydra-booking <= 1.1.32 (CVE-2025-68027)
 *   HostsController::CreateHosts() — wp_create_user() from raw request-supplied
 *   username/email/password, then $user->set_role('tfhb_host'), gated only by a
 *   REST permission_callback checking a custom capability that the 'tfhb_host'
 *   role itself also holds (self-registerable via a public signup shortcode).
 */

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// wp_create_user() + set_role() to a custom/elevated role, no capability check —
// the hydra-booking CreateHosts() shape.
// ruleid: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
function rest_create_host_no_auth() {
    $request = json_decode( file_get_contents( 'php://input' ), true );
    $user_id = wp_create_user( sanitize_text_field( $request['username'] ), sanitize_text_field( $request['password'] ), sanitize_text_field( $request['email'] ) );
    $user = new WP_User( $user_id );
    $user->set_role( 'vendor_host' );
    return rest_ensure_response( array( 'status' => true ) );
}

// wp_insert_user() + set_role() to an elevated role, no capability check.
// ruleid: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
function ajax_create_manager_no_auth() {
    $uid = wp_insert_user( array(
        'user_login' => sanitize_user( $_POST['username'] ),
        'user_pass'  => $_POST['password'],
        'user_email' => sanitize_email( $_POST['email'] ),
    ) );
    $user = new WP_User( $uid );
    $user->set_role( 'store_manager' );
    wp_send_json_success();
}

// wp_insert_user(array(..., "role" => $ROLE, ...)) inline literal, no capability check.
// ruleid: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
function rest_register_affiliate_no_auth( $request ) {
    $uid = wp_insert_user( array(
        'user_login' => sanitize_user( $request['username'] ),
        'user_pass'  => $request['password'],
        'user_email' => sanitize_email( $request['email'] ),
        'role'       => 'affiliate_manager',
    ) );
    return rest_ensure_response( array( 'id' => $uid ) );
}

// wp_update_user(array(..., 'role' => $ROLE, ...)) promoting an existing account,
// no capability check.
// ruleid: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
function ajax_promote_user_no_auth() {
    $target_id = absint( $_POST['user_id'] );
    wp_update_user( array(
        'ID'   => $target_id,
        'role' => 'shop_manager',
    ) );
    wp_send_json_success();
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// current_user_can('manage_options') guard — the hydra-booking 1.1.33 fix shape.
function rest_create_host_with_capability_check() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return rest_ensure_response( array( 'status' => false, 'message' => 'Insufficient permissions.' ) );
    }
    $request = json_decode( file_get_contents( 'php://input' ), true );
    // ok: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
    $user_id = wp_create_user( sanitize_text_field( $request['username'] ), sanitize_text_field( $request['password'] ), sanitize_text_field( $request['email'] ) );
    // ok: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
    $user = new WP_User( $user_id );
    $user->set_role( 'vendor_host' );
    return rest_ensure_response( array( 'status' => true ) );
}

// current_user_can('create_users') guard, ternary-assignment form.
function ajax_create_manager_with_capability_check() {
    $allowed = current_user_can( 'create_users' ) ? true : false;
    if ( ! $allowed ) {
        wp_send_json_error();
    }
    $uid = wp_insert_user( array(
        'user_login' => sanitize_user( $_POST['username'] ),
        'user_pass'  => $_POST['password'],
        'user_email' => sanitize_email( $_POST['email'] ),
    ) );
    // ok: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
    $user = new WP_User( $uid );
    $user->set_role( 'store_manager' );
}

// Role is the conventionally low-risk 'subscriber' default — public
// self-registration into 'subscriber' is not the privilege-escalation shape
// this rule targets.
function rest_public_signup_subscriber( $request ) {
    // ok: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
    $uid = wp_insert_user( array(
        'user_login' => sanitize_user( $request['username'] ),
        'user_pass'  => $request['password'],
        'user_email' => sanitize_email( $request['email'] ),
        'role'       => 'subscriber',
    ) );
    return rest_ensure_response( array( 'id' => $uid ) );
}

// 'customer' role (WooCommerce default) — same reasoning as 'subscriber'.
function ajax_public_signup_customer() {
    // ok: claude.php.wordpress.access-control.user-creation-role-elevation-no-capability-check
    wp_update_user( array(
        'ID'   => get_current_user_id(),
        'role' => 'customer',
    ) );
}
