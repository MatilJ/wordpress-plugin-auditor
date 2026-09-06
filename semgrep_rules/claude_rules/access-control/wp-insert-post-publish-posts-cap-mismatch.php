<?php
// claude.php.wordpress.access-control.wp-insert-post-publish-posts-cap-mismatch test cases
// Annotation placement: comment goes on the line immediately before the matched expression.
// The rule fires at the current_user_can('publish_posts') expression, not at the function start.

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// REST handler body checks publish_posts (Author+) then inserts a custom CPT.
// Mirrors CheckForm.php:135: CPT maps publish_posts => publish_emailkit (admin-only).
function vulnerable_rest_handler( $request ) {
    $form_id = $request->get_param( 'form_id' );
    // ruleid: claude.php.wordpress.access-control.wp-insert-post-publish-posts-cap-mismatch
    if ( ! current_user_can( 'publish_posts' ) ) {
        return new WP_Error( 'forbidden', 'Access denied', [ 'status' => 403 ] );
    }
    $post_data = [
        'post_type'   => 'my_cpt',
        'post_status' => 'publish',
        'post_title'  => sanitize_text_field( $request->get_param( 'title' ) ),
        'meta_input'  => [ 'my_cpt_status' => 'active' ],
    ];
    $post_id = wp_insert_post( $post_data );
    return [ 'post_id' => $post_id ];
}

// AJAX handler variant — nonce check then publish_posts guard, then wp_insert_post.
function vulnerable_ajax_handler() {
    check_ajax_referer( 'my_action_nonce', 'nonce' );
    // ruleid: claude.php.wordpress.access-control.wp-insert-post-publish-posts-cap-mismatch
    if ( ! current_user_can( 'publish_posts' ) ) {
        wp_send_json_error( 'Unauthorized' );
        wp_die();
    }
    $title = sanitize_text_field( wp_unslash( $_POST['title'] ) );
    $id    = wp_insert_post( [
        'post_type'   => 'my_custom_cpt',
        'post_status' => 'publish',
        'post_title'  => $title,
    ] );
    wp_send_json_success( [ 'id' => $id ] );
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// manage_options gate present — pattern-not-inside suppresses the publish_posts match.
function safe_handler_manage_options( $request ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        return new WP_Error( 'forbidden', 'Admin only', [ 'status' => 403 ] );
    }
    // ok: claude.php.wordpress.access-control.wp-insert-post-publish-posts-cap-mismatch
    if ( ! current_user_can( 'publish_posts' ) ) {
        return new WP_Error( 'forbidden', 'Insufficient cap', [ 'status' => 403 ] );
    }
    wp_insert_post( [ 'post_type' => 'my_cpt', 'post_status' => 'publish', 'post_title' => 'Safe' ] );
}

// CPT-specific capability — publish_posts never called; rule does not fire.
function safe_handler_cpt_specific_cap( $request ) {
    if ( ! current_user_can( 'publish_my_cpts' ) ) {
        return new WP_Error( 'forbidden', 'Admin only', [ 'status' => 403 ] );
    }
    wp_insert_post( [ 'post_type' => 'my_cpt', 'post_status' => 'publish', 'post_title' => 'Safe' ] );
}

// administrator role check — pattern-not-inside suppresses the publish_posts match.
function safe_handler_administrator_role( $request ) {
    if ( ! current_user_can( 'administrator' ) ) {
        return new WP_Error( 'forbidden', 'Admin only', [ 'status' => 403 ] );
    }
    // ok: claude.php.wordpress.access-control.wp-insert-post-publish-posts-cap-mismatch
    if ( ! current_user_can( 'publish_posts' ) ) {
        return new WP_Error( 'forbidden', 'Cannot publish', [ 'status' => 403 ] );
    }
    wp_insert_post( [ 'post_type' => 'my_cpt', 'post_status' => 'publish', 'post_title' => 'Safe' ] );
}

// No publish_posts check at all — no match candidate for the rule.
function no_publish_posts_check( $request ) {
    check_ajax_referer( 'action_nonce', 'nonce' );
    wp_insert_post( [ 'post_type' => 'my_cpt', 'post_status' => 'draft', 'post_title' => 'Draft' ] );
}
