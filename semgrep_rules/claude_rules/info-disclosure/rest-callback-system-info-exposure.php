<?php

function debug_endpoint_phpversion() {
    $response = ['php' => phpversion()];
    // ruleid: claude.php.wordpress.info-disclosure.rest-callback-system-info-exposure
    return wp_send_json($response, 200);
}

function debug_endpoint_wp_version() {
    global $wp_version;
    $response = ['wordpress' => $wp_version];
    // ruleid: claude.php.wordpress.info-disclosure.rest-callback-system-info-exposure
    return wp_send_json($response, 200);
}

function debug_endpoint_rest_response() {
    global $wp_version;
    // ruleid: claude.php.wordpress.info-disclosure.rest-callback-system-info-exposure
    return new WP_REST_Response(['version' => $wp_version], 200);
}

function debug_endpoint_php_constant() {
    $data = ['php' => PHP_VERSION];
    // ruleid: claude.php.wordpress.info-disclosure.rest-callback-system-info-exposure
    wp_send_json_success($data);
}

// ok: claude.php.wordpress.info-disclosure.rest-callback-system-info-exposure
function safe_table_prefix_usage() {
    global $wpdb;
    $table = $wpdb->prefix . "my_table";
    $results = $wpdb->get_results("SELECT * FROM $table LIMIT 1");
    return rest_ensure_response($results);
}

function safe_version_comparison() {
    global $wp_version;
    if (version_compare($wp_version, '6.0', '>=')) {
        // ok: claude.php.wordpress.info-disclosure.rest-callback-system-info-exposure
        return rest_ensure_response(['compatible' => true]);
    }
    // ok: claude.php.wordpress.info-disclosure.rest-callback-system-info-exposure
    return rest_ensure_response(['compatible' => false]);
}
