<?php
// wp-user-query-unfiltered-args test cases

// --- Vulnerable patterns ---

// REST body args passed directly to WP_User_Query — exact pattern from generateblocks audit
function vulnerable_get_user_query_rest( WP_REST_Request $request ) {
    $args = $request->get_param( 'args' ) ?? [];
    // ruleid: claude.php.wordpress.auth.wp-user-query-unfiltered-args
    $query = new WP_User_Query( $args );
    return $query->get_results();
}

// $_POST args passed directly to WP_User_Query
function vulnerable_get_user_query_post() {
    $args = $_POST['query_args'];
    // ruleid: claude.php.wordpress.auth.wp-user-query-unfiltered-args
    $query = new WP_User_Query( $args );
    return $query->get_results();
}

// REST get_json_params flowing to WP_User_Query
function vulnerable_json_params( WP_REST_Request $request ) {
    $args = $request->get_json_params();
    // ruleid: claude.php.wordpress.auth.wp-user-query-unfiltered-args
    $q = new WP_User_Query( $args );
    return $q->get_results();
}

// --- Safe patterns ---

// Hardcoded args array — no taint source; rule should not fire
function safe_hardcoded_args() {
    $args = [
        'role'   => 'subscriber',
        'fields' => 'all',
        'number' => 50,
    ];
    // ok: claude.php.wordpress.auth.wp-user-query-unfiltered-args
    $query = new WP_User_Query( $args );
    return $query->get_results();
}

// Only sanitized keys from user input; $args constructed as safe array
function safe_allowlisted_args( WP_REST_Request $request ) {
    $role = sanitize_key( $request->get_param( 'role' ) );
    $args = [
        'role'   => $role,
        'fields' => 'all',
        'number' => absint( $request->get_param( 'number' ) ),
    ];
    // ok: claude.php.wordpress.auth.wp-user-query-unfiltered-args
    $query = new WP_User_Query( $args );
    return $query->get_results();
}

// Numeric cast — can never produce a field-array payload
function safe_int_arg( WP_REST_Request $request ) {
    $per_page = (int) $request->get_param( 'per_page' );
    $args     = [ 'number' => $per_page, 'fields' => 'all' ];
    // ok: claude.php.wordpress.auth.wp-user-query-unfiltered-args
    $query = new WP_User_Query( $args );
    return $query->get_results();
}
