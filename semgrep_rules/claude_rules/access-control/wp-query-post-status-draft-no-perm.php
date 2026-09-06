<?php
// Test cases for claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
// Pattern rule: WP_Query / get_posts with post_status='draft' and no author/perm scoping.

// ─── Vulnerable patterns ──────────────────────────────────────────────────────

// WP_Query: post_status='draft', no author restriction. Match is on the assignment line.
function get_all_drafts() {
    $args = array( 'post_type' => 'post', 'posts_per_page' => 10 );
    // ruleid: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'draft';
    return new WP_Query( $args );
}

// WP_Query: post_status=array including 'draft', no author/perm restriction.
function get_pages_all_authors() {
    $args = array( 'post_type' => array( 'page', 'post' ), 'posts_per_page' => 20 );
    // ruleid: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = array( 'publish', 'draft' );
    return new WP_Query( $args );
}

// get_posts(): post_status='draft', no author restriction.
function fetch_draft_posts() {
    $args = array( 'post_type' => 'page', 'numberposts' => -1 );
    // ruleid: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'draft';
    return get_posts( $args );
}

// get_posts(): post_status array including 'draft', no author restriction.
function fetch_drafts_and_published() {
    $args = array( 'post_type' => 'post' );
    // ruleid: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = array( 'publish', 'draft' );
    return get_posts( $args );
}

// WP_Query: post_status='any', no author restriction.
function get_all_any_status() {
    $args = array( 'post_type' => 'post', 'posts_per_page' => 10 );
    // ruleid: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'any';
    return new WP_Query( $args );
}

// get_posts(): post_status='any', no author restriction.
function fetch_any_status_posts() {
    $args = array( 'post_type' => 'page', 'numberposts' => -1 );
    // ruleid: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'any';
    return get_posts( $args );
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// post_status='publish' only — no draft, so no cross-author disclosure.
function get_published_only() {
    $args = array( 'post_type' => 'post' );
    // ok: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'publish';
    return new WP_Query( $args );
}

// post_status='draft' but author-scoped to current user — safe.
function get_my_drafts() {
    $args                = array( 'post_type' => 'post' );
    $args['author']      = get_current_user_id();
    // ok: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'draft';
    return new WP_Query( $args );
}

// post_status array with 'draft' and perm='readable' restriction.
function get_readable_drafts() {
    $args         = array( 'post_type' => 'post' );
    $args['perm'] = 'readable';
    // ok: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = array( 'publish', 'draft' );
    return new WP_Query( $args );
}

// get_posts() with 'draft' scoped to current author — safe.
function get_my_draft_posts() {
    $args            = array( 'post_type' => 'post' );
    $args['author']  = get_current_user_id();
    // ok: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'draft';
    return get_posts( $args );
}

// get_posts() with 'draft' and author__in — safe.
function get_team_drafts( $user_ids ) {
    $args                = array( 'post_type' => 'post' );
    $args['author__in']  = $user_ids;
    // ok: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = array( 'publish', 'draft' );
    return get_posts( $args );
}

// post_status='any' but author-scoped to current user — safe.
function get_my_any_status() {
    $args            = array( 'post_type' => 'post' );
    $args['author']  = get_current_user_id();
    // ok: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'any';
    return new WP_Query( $args );
}

// post_status='any' with perm='readable' — safe.
function get_any_readable() {
    $args         = array( 'post_type' => 'post' );
    $args['perm'] = 'readable';
    // ok: claude.php.wordpress.access-control.wp-query-post-status-draft-no-perm
    $args['post_status'] = 'any';
    return new WP_Query( $args );
}
