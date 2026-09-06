<?php
// claude.php.wordpress.access-control.ajax-nonce-only-post-userid-to-call test cases

// ── Vulnerable patterns (should fire) ────────────────────────────────────────

// Mirrors user-registration v5.1.6 cancel_email_change():
// nonce check + absint($_POST[...]) user_id + static method call, no ownership check.
// ruleid: claude.php.wordpress.access-control.ajax-nonce-only-post-userid-to-call
function cancel_email_change() {
    check_ajax_referer( 'cancel_email_change_nonce', '_wpnonce' );
    $user_id = isset( $_POST['cancel_email_change'] ) ? absint( wp_unslash( $_POST['cancel_email_change'] ) ) : false;
    if ( ! $user_id ) {
        wp_die( -1 );
    }
    PluginHelper::delete_pending_email_change( $user_id );
    wp_send_json_success( array( 'message' => 'Cancelled.' ) );
}

// Instance method call variant — user_id from POST to $obj->update($uid, ...).
// ruleid: claude.php.wordpress.access-control.ajax-nonce-only-post-userid-to-call
function revoke_token_for_user() {
    check_ajax_referer( 'revoke_token_nonce', 'security' );
    $user_id = absint( $_POST['user_id'] );
    $this->token_service->revoke( $user_id, 'plugin_api_token' );
    wp_send_json_success();
}

// ── Safe patterns (should NOT fire) ──────────────────────────────────────────

// Has current_user_can('edit_user', ...) ownership check — safe.
// ok: claude.php.wordpress.access-control.ajax-nonce-only-post-userid-to-call
function cancel_email_change_safe() {
    check_ajax_referer( 'cancel_email_change_nonce', '_wpnonce' );
    $user_id = isset( $_POST['cancel_email_change'] ) ? absint( wp_unslash( $_POST['cancel_email_change'] ) ) : false;
    if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
        wp_die( -1 );
    }
    PluginHelper::delete_pending_email_change( $user_id );
    wp_send_json_success();
}

// Has current_user_can('manage_options') — admin-only handler, out of scope.
// ok: claude.php.wordpress.access-control.ajax-nonce-only-post-userid-to-call
function admin_delete_user_data() {
    check_ajax_referer( 'admin_action_nonce', '_wpnonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( -1 );
    }
    $user_id = absint( $_POST['user_id'] );
    DataManager::purge( $user_id, 'all' );
    wp_send_json_success();
}

// Has current_user_can('edit_users') — broad admin capability.
// ok: claude.php.wordpress.access-control.ajax-nonce-only-post-userid-to-call
function bulk_suspend_users() {
    check_ajax_referer( 'suspend_users_nonce', '_wpnonce' );
    if ( ! current_user_can( 'edit_users' ) ) {
        wp_die( -1 );
    }
    $user_id = absint( $_POST['user_id'] );
    UserManager::suspend( $user_id );
    wp_send_json_success();
}
