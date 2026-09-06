<?php
// Test cases for claude.php.wordpress.sqli.wpdb-prepare-unquoted-in-clause-placeholder

function rrtngg_delete_leads_shape() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'rratingg_leads';
    $ids = array_map( 'sanitize_text_field', $_POST['lead_ids'] );
    $ids_in = implode( ', ', $ids );
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-unquoted-in-clause-placeholder
    $sql = $wpdb->prepare( "DELETE FROM {$table_name} WHERE ID IN (%s)", $ids_in );
    return $wpdb->query( $sql );
}

function bulk_select_by_id_list() {
    global $wpdb;
    $ids = array_map( 'trim', $_GET['ids'] );
    $list = implode( ',', $ids );
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-unquoted-in-clause-placeholder
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items WHERE ID IN (%s)", $list ) );
}

function delete_leads_int_cast() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'rratingg_leads';
    $ids = array_map( 'absint', $_POST['lead_ids'] );
    $ids_in = implode( ', ', $ids );
    // ok: claude.php.wordpress.sqli.wpdb-prepare-unquoted-in-clause-placeholder
    $sql = $wpdb->prepare( "DELETE FROM {$table_name} WHERE ID IN (%s)", $ids_in );
    return $wpdb->query( $sql );
}

function delete_leads_gated_behind_capability() {
    global $wpdb;
    if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Unauthorized' );
    }
    check_ajax_referer( 'snth_nonce', 'nonce' );
    $table_name = $wpdb->prefix . 'rratingg_leads';
    $ids = array_map( 'sanitize_text_field', $_POST['lead_ids'] );
    $ids_in = implode( ', ', $ids );
    // ok: claude.php.wordpress.sqli.wpdb-prepare-unquoted-in-clause-placeholder
    $sql = $wpdb->prepare( "DELETE FROM {$table_name} WHERE ID IN (%s)", $ids_in );
    return $wpdb->query( $sql );
}

function normal_db_read_by_single_id() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'rratingg_leads';
    $id = sanitize_text_field( $_GET['id'] );
    // ok: claude.php.wordpress.sqli.wpdb-prepare-unquoted-in-clause-placeholder
    $sql = $wpdb->prepare( "SELECT * FROM {$table_name} WHERE ID = '%s'", $id );
    return $wpdb->get_row( $sql, ARRAY_A );
}
