<?php

function get_system_info_callback() {
    global $wpdb;
    // ruleid: claude.php.wordpress.info-disclosure.wpdb-prefix-in-response
    wp_send_json_success( array(
        'prefix' => $wpdb->prefix,
        'php'    => phpversion(),
    ) );
}

function rest_db_info() {
    global $wpdb;
    $info = array( 'table_prefix' => $wpdb->prefix );
    // ruleid: claude.php.wordpress.info-disclosure.wpdb-prefix-in-response
    return new WP_REST_Response( $info, 200 );
}

function get_posts_from_db() {
    global $wpdb;
    $table = $wpdb->prefix . 'posts';
    $results = $wpdb->get_results( "SELECT ID, post_title FROM $table WHERE post_status = 'publish'" );
    // ok: claude.php.wordpress.info-disclosure.wpdb-prefix-in-response
    wp_send_json_success( $results );
}

function use_prefix_in_query_only() {
    global $wpdb;
    $count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}options" );
    // ok: claude.php.wordpress.info-disclosure.wpdb-prefix-in-response
    wp_send_json_success( array( 'count' => $count ) );
}
