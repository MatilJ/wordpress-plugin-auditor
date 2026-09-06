<?php
/**
 * Test cases for claude.php.wordpress.access-control.wp-query-perm-readable
 *
 * Rule: Flags WP_Query or get_posts using perm='readable', which only
 * author-scopes 'private' status — draft/pending/future/trash are unrestricted.
 */

global $wpdb;

// ── TRUE POSITIVE: variable-args pattern ─────────────────────────────────────
// Shortcode callback builds args array with perm=readable; post_status is
// user-supplied via shortcode attribute. All non-private statuses are exposed.

function test_shortcode_perm_readable_variable( $atts ) {
    $args             = array();
    $args['post_type'] = 'post';
    // ruleid: claude.php.wordpress.access-control.wp-query-perm-readable
    $args['perm']     = 'readable';
    $args['post_status'] = sanitize_text_field( $atts['post_status'] ); // user-controlled
    $query = new WP_Query( $args );
    return $query->have_posts();
}


// ── TRUE POSITIVE: inline array literal passed to new WP_Query ───────────────

function test_inline_wp_query( $post_status ) {
    // ruleid: claude.php.wordpress.access-control.wp-query-perm-readable
    $query = new WP_Query( array( 'perm' => 'readable', 'post_status' => $post_status ) );
    return $query;
}


// ── TRUE POSITIVE: inline array literal passed to get_posts ──────────────────

function test_inline_get_posts( $post_status ) {
    // ruleid: claude.php.wordpress.access-control.wp-query-perm-readable
    return get_posts( array( 'perm' => 'readable', 'post_status' => $post_status ) );
}


// ── FALSE POSITIVE: perm=editable — correctly author-scopes all statuses ─────
// perm=editable adds post_author restriction to draft/pending/future/trash too.

function test_perm_editable( $post_status ) {
    $args = array();
    // ok: claude.php.wordpress.access-control.wp-query-perm-readable
    $args['perm']        = 'editable';
    $args['post_status'] = $post_status;
    return new WP_Query( $args );
}


// ── TRUE POSITIVE: array initialization with perm=readable ───────────────────
// Plugin initializes args array with perm key; WP_Query called after further args added.

function test_array_init_perm_readable( $post_status ) {
    // ruleid: claude.php.wordpress.access-control.wp-query-perm-readable
    $args = array( 'perm' => 'readable', 'post_type' => 'post' );
    $args['post_status'] = $post_status;
    return new WP_Query( $args );
}


// ── TRUE POSITIVE: perm=readable assigned even when WP_Query is called by caller
// Variable-pattern fires on the assignment regardless of call site.

function build_readable_args( $post_type ) {
    $args = array( 'post_type' => $post_type );
    // ruleid: claude.php.wordpress.access-control.wp-query-perm-readable
    $args['perm'] = 'readable';
    return $args;
}


// ── FALSE POSITIVE: inline array with perm=editable — does not match ─────────

function test_inline_perm_editable( $post_status ) {
    // ok: claude.php.wordpress.access-control.wp-query-perm-readable
    return get_posts( array( 'perm' => 'editable', 'post_status' => $post_status ) );
}
