<?php
// Test file for is-admin-auth-method-no-cap-check rule

// --- TRUE POSITIVES ---

// Static oauth-named method inside is_admin() without cap check.
// Mirrors googleanalytics 3.3.1: Ga_Admin::init_oauth() called in Ga_Helper::init()
// hooked to 'init', internally calling update_option() without capability gate.
function ga_helper_init_no_cap() {
    if ( is_admin() ) {
        Ga_Admin::add_filters();
        Ga_Admin::add_actions();
        // ruleid: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
        Ga_Admin::init_oauth();
    }
}

// Instance method with auth-related name, no cap check.
function plugin_init_no_cap() {
    if ( is_admin() ) {
        // ruleid: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
        $this->connect_account();
    }
}

// Static setup method inside is_admin() without cap check.
function plugin_setup_no_cap() {
    if ( is_admin() ) {
        // ruleid: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
        Plugin_Config::setup_credentials();
    }
}

// Instance configure method inside is_admin() without cap check.
function plugin_configure_no_cap() {
    if ( is_admin() ) {
        // ruleid: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
        $api->configure_token();
    }
}

// Branch 2 — negated guard-clause form (CWE-266 privilege-escalation variant).
// !is_admin() OR'd with an emptiness check is used as the entire authorization
// gate for an AJAX-style handler, then a per-user privilege flag is written.
function ajax_update_admin_status() {
    $user_id = !empty($_POST['user_id']) ? intval($_POST['user_id']) : '';
    $status  = !empty($_POST['status'])  ? intval($_POST['status'])  : '';
    // ruleid: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
    if ( !is_admin() || empty($user_id) ) {
        wp_send_json( array( 'type' => 'error' ) );
    }
    update_user_meta( $user_id, 'is_privileged_flag', $status );
}

// Bare !is_admin() guard (no OR'd condition), add_user_meta sink.
function ajax_set_admin_flag() {
    $user_id = intval( $_POST['user_id'] );
    // ruleid: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
    if ( !is_admin() ) {
        wp_send_json_error();
    }
    add_user_meta( $user_id, 'account_level', 1 );
}

// --- FALSE POSITIVES (ok cases) ---

// Branch 2 fix shape: a real capability check is added as a flat statement
// between the is_admin() guard-clause and the privileged write.
function ajax_update_admin_status_fixed() {
    $user_id = !empty($_POST['user_id']) ? intval($_POST['user_id']) : '';
    // ok: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
    if ( !is_admin() || empty($user_id) ) {
        wp_send_json( array( 'type' => 'error' ) );
    }
    current_user_can( 'manage_options' );
    update_user_meta( $user_id, 'is_privileged_flag', 1 );
}

// Branch 2 scope limit: is_admin()-only-gated action whose sink is not a
// user-meta/capability write (out of scope for this rule's sink set).
function ajax_log_action_only() {
    $user_id = intval( $_POST['user_id'] );
    // ok: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
    if ( !is_admin() ) {
        wp_send_json_error();
    }
    log_user_action( $user_id, 'note', 'viewed' );
}

// Cap check present at is_admin() scope — not a missing authorization issue.
function ga_helper_init_with_cap() {
    if ( is_admin() ) {
        if ( current_user_can( 'manage_options' ) ) {
            // ok: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
            Ga_Admin::init_oauth();
        }
    }
}

// Cap check via flat statement before the call.
function plugin_flat_cap_check() {
    if ( is_admin() ) {
        current_user_can( 'manage_options' );
        // ok: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
        $this->connect_account();
    }
}

// Method name does not match the auth/oauth/token/connect regex — not flagged.
function plugin_non_auth_method() {
    if ( is_admin() ) {
        // ok: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
        Ga_Admin::add_filters();
        // ok: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
        Ga_Admin::add_actions();
    }
}

// Call outside is_admin() block — not in scope of this rule.
function not_in_admin_block() {
    // ok: claude.php.wordpress.access-control.is-admin-auth-method-no-cap-check
    Some_Class::init_oauth();
}
