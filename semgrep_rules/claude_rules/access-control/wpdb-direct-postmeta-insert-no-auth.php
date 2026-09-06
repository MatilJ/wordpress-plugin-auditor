<?php
// Test file for wpdb-direct-postmeta-insert-no-auth rule

// --- TRUE POSITIVES ---

// TP1: Direct $wpdb->insert on postmeta without any auth check (CVE-2026-2301 pattern)
function duplicate_post_meta_vulnerable( $original_id, $duplicate_id ) {
    global $wpdb;
    $post_meta = get_post_meta( $original_id );
    foreach ( $post_meta as $key => $values ) {
        foreach ( $values as $meta_value ) {
            $data = array(
                'post_id'    => intval( $duplicate_id ),
                'meta_key'   => sanitize_text_field( $key ),
                'meta_value' => $meta_value,
            );
            $formats = array( '%d', '%s', '%s' );
            // ruleid: claude.php.wordpress.access-control.wpdb-direct-postmeta-insert-no-auth
            $wpdb->insert( $wpdb->prefix . 'postmeta', $data, $formats );
        }
    }
}

// TP2: Direct $wpdb->update on postmeta without auth
function update_meta_value_no_auth( $post_id, $meta_key, $new_value ) {
    global $wpdb;
    // ruleid: claude.php.wordpress.access-control.wpdb-direct-postmeta-insert-no-auth
    $wpdb->update(
        $wpdb->prefix . 'postmeta',
        array( 'meta_value' => $new_value ),
        array( 'post_id' => $post_id, 'meta_key' => $meta_key )
    );
}

// TP3: Using $wpdb->postmeta property
function clone_meta_wpdb_property( $src, $dst ) {
    global $wpdb;
    $meta = $wpdb->get_results( "SELECT * FROM $wpdb->postmeta WHERE post_id = $src" );
    foreach ( $meta as $row ) {
        // ruleid: claude.php.wordpress.access-control.wpdb-direct-postmeta-insert-no-auth
        $wpdb->insert( $wpdb->postmeta, array(
            'post_id'    => $dst,
            'meta_key'   => $row->meta_key,
            'meta_value' => $row->meta_value,
        ));
    }
}

// --- TRUE NEGATIVES ---

// TN1: Inside manage_options gate
function admin_only_meta_insert( $post_id ) {
    global $wpdb;
    if ( current_user_can( 'manage_options' ) ) {
        // ok: claude.php.wordpress.access-control.wpdb-direct-postmeta-insert-no-auth
        $wpdb->insert( $wpdb->prefix . 'postmeta', array(
            'post_id'    => $post_id,
            'meta_key'   => '_settings',
            'meta_value' => 'data',
        ));
    }
}
