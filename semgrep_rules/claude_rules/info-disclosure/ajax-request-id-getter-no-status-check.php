<?php
// Test cases for claude.php.wordpress.info-disclosure.ajax-request-id-getter-no-status-check

// === TRUE POSITIVES — should match ===

// Public AJAX handler reads an item ID straight from the request (framework
// array-accessor form) and returns settings for it with no existence/status
// check. Any unauthenticated visitor can read draft/private item settings.
function handle_get_item_settings() {
    $request = ninja_request();
    $itemId  = intval( Arr::get( $request, 'item_id' ) );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-request-id-getter-no-status-check
    $settings = my_plugin_get_item_settings( $itemId, 'public' );
    wp_send_json( $settings, 200 );
}

// Same class via raw superglobal access instead of a framework helper.
function handle_get_table_columns() {
    $tableId = absint( $_REQUEST['table_id'] );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-request-id-getter-no-status-check
    $columns = my_plugin_get_table_columns( $tableId );
    wp_send_json( $columns, 200 );
}

// === FALSE POSITIVES — should NOT match ===

// Safe: get_post() existence/type/status check before fetching data.
function handle_get_item_settings_safe() {
    $request = ninja_request();
    $itemId  = intval( Arr::get( $request, 'item_id' ) );
    $post    = get_post( $itemId );
    if ( ! $post || $post->post_type !== 'my-item' || $post->post_status !== 'publish' ) {
        wp_send_json( [], 200 );
    }
    // ok: claude.php.wordpress.info-disclosure.ajax-request-id-getter-no-status-check
    $settings = my_plugin_get_item_settings( $itemId, 'public' );
    wp_send_json( $settings, 200 );
}

// Safe: capability check gates the whole handler.
function handle_get_table_columns_safe() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json( [], 403 );
    }
    $tableId = absint( $_REQUEST['table_id'] );
    // ok: claude.php.wordpress.info-disclosure.ajax-request-id-getter-no-status-check
    $columns = my_plugin_get_table_columns( $tableId );
    wp_send_json( $columns, 200 );
}
