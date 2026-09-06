<?php

// Test cases for claude.php.wordpress.access-control.init-hook-no-auth-option-write

add_action( 'init', 'import_settings_from_uploaded_file' );
// ruleid: claude.php.wordpress.access-control.init-hook-no-auth-option-write
function import_settings_from_uploaded_file() {
    if ( isset( $_POST['plugin_import'] ) ) {
        $json = file_get_contents( $_FILES['import_file']['tmp_name'] );
        $entries = json_decode( $json );
        foreach ( $entries as $entry ) {
            update_option( $entry->option_name, $entry->option_value );
        }
    }
}

add_action( 'wp_loaded', 'reset_plugin_option_from_request' );
// ruleid: claude.php.wordpress.access-control.init-hook-no-auth-option-write
function reset_plugin_option_from_request() {
    $name = $_GET['name'];
    $value = $_GET['value'];
    update_option( $name, $value );
}

add_action( 'init', 'import_settings_with_capability_check' );
// ok: claude.php.wordpress.access-control.init-hook-no-auth-option-write
function import_settings_with_capability_check() {
    if ( isset( $_POST['plugin_import'] ) && current_user_can( 'administrator' ) ) {
        $json = file_get_contents( $_FILES['import_file']['tmp_name'] );
        $entries = json_decode( $json );
        foreach ( $entries as $entry ) {
            update_option( $entry->option_name, $entry->option_value );
        }
    }
}

add_action( 'init', 'import_settings_with_nonce_check' );
// ok: claude.php.wordpress.access-control.init-hook-no-auth-option-write
function import_settings_with_nonce_check() {
    check_admin_referer( 'plugin_import_action' );
    if ( isset( $_POST['plugin_import'] ) ) {
        $json = file_get_contents( $_FILES['import_file']['tmp_name'] );
        $entries = json_decode( $json );
        foreach ( $entries as $entry ) {
            update_option( $entry->option_name, $entry->option_value );
        }
    }
}

// Safe: no request data consumed anywhere in this function — a hardcoded
// endpoint slug is force-synced into the option only when the option's own
// current value drifts from the constant, a one-time rewrite-rule self-heal.
add_action( 'init', 'sync_custom_endpoint_slug_once' );
// ok: claude.php.wordpress.access-control.init-hook-no-auth-option-write
function sync_custom_endpoint_slug_once() {
    $current_rewrite_rule = get_option( 'my_plugin_custom_tab' );
    if ( ! $current_rewrite_rule || MY_PLUGIN_CUSTOM_ENDPOINT !== $current_rewrite_rule ) {
        flush_rewrite_rules( true );
        update_option( 'my_plugin_custom_tab', MY_PLUGIN_CUSTOM_ENDPOINT );
    }
}
