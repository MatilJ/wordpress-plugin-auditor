<?php
/**
 * Test cases for claude.php.wordpress.access.rest-arbitrary-post-type-query
 *
 * The rule fires when a user-supplied value (REST param or superglobal) flows
 * directly into get_posts() or new WP_Query() as the 'post_type' array key
 * without a capability check or post_type allowlist. get_posts()/WP_Query do
 * NOT enforce CPT capability arrays — only the WP REST API router does.
 */

// ── TRUE POSITIVES — user-supplied post_type with no allowlist/cap check ──────

// REST param → sanitize_text_field() → get_posts(array syntax) — no allowlist
// Confirmed TP: Finding 1 in getwid 2.2.0 rest-api.php:282 (get_templates())
function get_templates( $object ) {
    $template_name = sanitize_text_field( wp_unslash( $_GET['template_name'] ) );
    $posts = get_posts( array(
        'numberposts' => -1,
        // ruleid: claude.php.wordpress.access.rest-arbitrary-post-type-query
        'post_type'   => $template_name,
    ) );
    $return = [];
    foreach ( $posts as $post ) {
        $return[] = array( 'value' => $post->ID, 'label' => $post->post_title );
    }
    return $return;
}

// REST request param → square bracket array syntax
function get_posts_by_type( WP_REST_Request $request ) {
    $post_type = sanitize_text_field( $request->get_param( 'post_type' ) );
    // ruleid: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $posts = get_posts( [ 'post_type' => $post_type, 'numberposts' => 50 ] );
    return $posts;
}

// $_POST → new WP_Query() — array() syntax
function ajax_query_by_type() {
    $type = sanitize_text_field( wp_unslash( $_POST['type'] ) );
    // ruleid: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $query = new WP_Query( array( 'post_type' => $type, 'posts_per_page' => 10 ) );
    return $query->posts;
}

// REST params batch → get_params() — square bracket WP_Query
function get_posts_by_params( WP_REST_Request $request ) {
    $params    = $request->get_params();
    $post_type = sanitize_text_field( $params['postType'] );
    // ruleid: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $query = new WP_Query( [ 'post_type' => $post_type, 'post_status' => 'publish' ] );
    return $query->posts;
}

// ── FALSE POSITIVES — should NOT match ────────────────────────────────────────

// Post type from stored option — developer-configured, not attacker-supplied
function get_posts_configured_type() {
    $post_type = get_option( 'plugin_post_type', 'post' );
    // ok: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $posts = get_posts( array( 'post_type' => $post_type, 'numberposts' => 10 ) );
    return $posts;
}

// Post type from get_post_type() — derives slug from existing post object
function get_related_posts( $post_id ) {
    $post_type = get_post_type( $post_id );
    // ok: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $posts = get_posts( array( 'post_type' => $post_type, 'numberposts' => 5 ) );
    return $posts;
}

// Numeric value — cannot be a valid post type slug
function get_posts_numeric_type() {
    $type_id = intval( $_POST['type_id'] );
    // ok: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $posts = get_posts( array( 'post_type' => $type_id, 'numberposts' => 10 ) );
    return $posts;
}

// Hardcoded string literal 'post_type' value — not user-supplied
// (rule won't fire: no taint source reaches $type)
function get_posts_hardcoded_type() {
    $type = 'post';
    // ok: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $posts = get_posts( array( 'post_type' => $type, 'numberposts' => 10 ) );
    return $posts;
}

// Handler with current_user_can() check — triage manually for CPT-level authorization
function get_posts_with_cap_check( WP_REST_Request $request ) {
    $post_type = sanitize_text_field( $request->get_param( 'type' ) );
    if ( ! current_user_can( 'manage_options' ) ) {
        return new WP_Error( 'unauthorized', 'Insufficient permissions', array( 'status' => 403 ) );
    }
    // ok: claude.php.wordpress.access.rest-arbitrary-post-type-query
    $posts = get_posts( array( 'post_type' => $post_type, 'numberposts' => -1 ) );
    return $posts;
}
