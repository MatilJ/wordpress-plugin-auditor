<?php
// Test fixture for claude.php.wordpress.access-control.user-input-to-account-state-meta

function bl_upgrade_plan_from_post() {
    $uid = get_current_user_id();
    // ruleid: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_user_meta( $uid, 'membership_level', $_POST['level'] );
}

function bl_set_account_status_from_get() {
    // ruleid: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_option( 'account_status', $_GET['status'] );
}

function bl_mark_verified_from_request_intval() {
    $uid = get_current_user_id();
    $v = absint( $_REQUEST['email_verified'] );
    // intval does not neutralize a logic-value choice — still attacker-chosen.
    // ruleid: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_user_meta( $uid, 'email_verified', $v );
}

function ok_cosmetic_meta_from_post() {
    $uid = get_current_user_id();
    // ok: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_user_meta( $uid, 'first_name', $_POST['fname'] );
}

function ok_account_state_from_server_value() {
    $uid = get_current_user_id();
    $level = get_user_meta( $uid, 'membership_level', true );
    // ok: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_user_meta( $uid, 'membership_level', $level );
}

function ok_account_state_literal() {
    $uid = get_current_user_id();
    // ok: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_user_meta( $uid, 'membership_level', 'free' );
}

function bl_enable_vendor_selling_from_json_body() {
    $json = file_get_contents('php://input');
    $params = json_decode($json, TRUE);
    $user_id = wp_insert_user(array('user_login' => $params['username']));
    if (isset($params['dokan_enable_selling'])) {
        $enable_selling = $params['dokan_enable_selling'];
    }
    // CVE-2025-3438 class: unauthenticated self-registration lets the caller
    // choose the marketplace vendor-selling-enabled flag directly.
    // ruleid: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_user_meta( $user_id, 'dokan_enable_selling', $enable_selling );
}

function bl_set_vendor_status_from_post() {
    $uid = get_current_user_id();
    // ruleid: claude.php.wordpress.access-control.user-input-to-account-state-meta
    update_user_meta( $uid, 'vendor_status', $_POST['vendor_status'] );
}

function ok_enable_selling_hardcoded_no() {
    $uid = get_current_user_id();
    $json = file_get_contents('php://input');
    $params = json_decode($json, TRUE);
    // CVE-2025-3438 fix shape: the value is a hardcoded literal, never the
    // attacker-controlled $params entry, regardless of what the client sends.
    if (isset($params['dokan_enable_selling'])) {
        // ok: claude.php.wordpress.access-control.user-input-to-account-state-meta
        update_user_meta( $uid, 'dokan_enable_selling', 'no' );
    }
}
