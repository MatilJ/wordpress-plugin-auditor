<?php
// Tests for claude.php.wordpress.access.admin-init-nonce-only-no-capability-write
// NOTE: join mode requires `semgrep login` — --test and standalone --config scans of
// this file will fail locally. Verify via sub-rule isolation or with login.

// ── TRUE POSITIVES ─────────────────────────────────────────────────────────────

// Case 1: string callback — nonce check, wp_update_post write, no capability check
add_action( 'admin_init', 'handle_template_action' );

// ruleid: claude.php.wordpress.access.admin-init-nonce-only-no-capability-write
function handle_template_action() {
    $action = sanitize_key( filter_input( INPUT_GET, 'action' ) );
    if ( 'set_active_template' === $action ) {
        $post = filter_input( INPUT_GET, 'post', FILTER_VALIDATE_INT );
        check_admin_referer( 'set_active_template_' . $post );
        wp_update_post( [ 'ID' => $post, 'post_status' => 'publish' ] );
    }
}

// Case 2: string callback — nonce check, update_option write, no capability check
add_action( 'admin_init', 'reset_plugin_settings' );

// ruleid: claude.php.wordpress.access.admin-init-nonce-only-no-capability-write
function reset_plugin_settings() {
    if ( isset( $_GET['action'] ) && 'reset_settings' === $_GET['action'] ) {
        check_admin_referer( 'reset_settings_nonce' );
        update_option( 'my_plugin_settings', [] );
    }
}

// ── FALSE POSITIVES (ok) ───────────────────────────────────────────────────────

// Case 3: nonce check plus capability check — safe
add_action( 'admin_init', 'gated_template_action' );

// ok: claude.php.wordpress.access.admin-init-nonce-only-no-capability-write
function gated_template_action() {
    $post = filter_input( INPUT_GET, 'post', FILTER_VALIDATE_INT );
    check_admin_referer( 'set_active_template_' . $post );
    if ( ! current_user_can( 'publish_posts' ) ) {
        wp_die( 'Insufficient permissions.' );
    }
    wp_update_post( [ 'ID' => $post, 'post_status' => 'publish' ] );
}

// Case 4: nonce check plus capability check before update_option — safe
add_action( 'admin_init', 'gated_settings_reset' );

// ok: claude.php.wordpress.access.admin-init-nonce-only-no-capability-write
function gated_settings_reset() {
    if ( ! isset( $_GET['action'] ) || 'reset_settings' !== $_GET['action'] ) {
        return;
    }
    check_admin_referer( 'reset_settings_nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Insufficient permissions.' );
    }
    update_option( 'my_plugin_settings', [] );
}
