<?php
// Test file for ajax-post-id-to-wp-update-post-no-ownership rule

// --- TRUE POSITIVES ---

// TP1: POST param flows to wp_update_post via array literal
function handle_update_no_auth() {
    $post_id = intval( $_POST['post_id'] );
    $title   = sanitize_text_field( $_POST['title'] );
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-post-no-ownership
    wp_update_post( array( 'ID' => $post_id, 'post_title' => $title ) );
    wp_die();
}

// TP2: REQUEST param flows to wp_update_post via variable assignment
function handle_update_via_var() {
    $post_id = intval( $_REQUEST['post_id'] );
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-post-no-ownership
    $args = array( 'ID' => $post_id, 'post_content' => 'new content' );
    wp_update_post( $args );
    wp_die();
}

// --- TRUE NEGATIVES ---

// TN1: Post ID comes from DB query (taint broken by sanitizer)
function handle_update_from_db() {
    global $wpdb;
    $slug = sanitize_text_field( $_POST['slug'] );
    $post_id = $wpdb->get_var( $wpdb->prepare( "SELECT ID FROM $wpdb->posts WHERE post_name = %s", $slug ) );
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-post-no-ownership
    wp_update_post( array( 'ID' => $post_id, 'post_title' => 'Updated' ) );
    wp_die();
}

// TN2: current_user_can('manage_options') gates the function via an
// if-condition guard (the common WP idiom) before the write — sitewide-admin
// gate makes per-resource ownership moot.
function handle_update_manage_options_if_guard() {
    $post_id = intval( $_POST['post_id'] );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Insufficient permissions.' );
    }
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-post-no-ownership
    wp_update_post( array( 'ID' => $post_id, 'post_title' => 'Updated' ) );
}

// TN3: current_user_can('manage_options') as a bare statement before the
// array-assignment sink shape.
function handle_update_manage_options_bare_statement() {
    $post_id = intval( $_REQUEST['post_id'] );
    current_user_can( 'manage_options' );
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-post-no-ownership
    $args = array( 'ID' => $post_id, 'post_content' => 'new content' );
    wp_update_post( $args );
}

// TP3: current_user_can('edit_posts') (class-level, no ID) does NOT satisfy
// the manage_options exclusion — must still fire.
function handle_update_class_level_capability_only() {
    $post_id = intval( $_POST['post_id'] );
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_die( 'Insufficient permissions.' );
    }
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-post-no-ownership
    wp_update_post( array( 'ID' => $post_id, 'post_title' => 'Updated' ) );
}
