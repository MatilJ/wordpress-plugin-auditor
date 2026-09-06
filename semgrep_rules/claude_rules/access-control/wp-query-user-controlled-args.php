<?php
// wp-query-user-controlled-args / wp-parse-args-user-wins-wp-query test cases

global $wpdb;

// ── Rule 1 (structural): wrong wp_parse_args order before WP_Query ────────────

// D-1 exact pattern: if-guard + wrong order; $args (defaults) overridden by $wp_query_args.
function structural_vulnerable_if_guard( $atts ) {
    $defaults      = array( 'post_status' => 'publish', 'numberposts' => 10 );
    $wp_query_args = $atts['wp_query_args'] ?? array();
    $args          = $defaults;
    if ( $wp_query_args ) {
        // ruleid: claude.php.wordpress.access-control.wp-parse-args-user-wins-wp-query
        $args = wp_parse_args( $wp_query_args, $args );
    }
    new WP_Query( $args );
}

// Direct wrong-order merge without an if-guard.
function structural_vulnerable_direct( $user_query_args ) {
    $args = array( 'post_type' => 'post', 'post_status' => 'publish' );
    // ruleid: claude.php.wordpress.access-control.wp-parse-args-user-wins-wp-query
    $args = wp_parse_args( $user_query_args, $args );
    new WP_Query( $args );
}

// Safe: correct argument order — hardcoded defaults are first arg and win.
function structural_safe_correct_order( $user_query_args ) {
    $args = array( 'post_type' => 'post', 'post_status' => 'publish' );
    // ok: claude.php.wordpress.access-control.wp-parse-args-user-wins-wp-query
    $args = wp_parse_args( $args, $user_query_args );
    new WP_Query( $args );
}

// Safe: $stored_options was itself populated from get_option() earlier in
// the same function — a stored plugin-settings merge, not request-controlled
// data, despite matching the "wrong order" wp_parse_args() shape.
function get_plugin_settings( $option_name, $defaults ) {
    $stored_options = get_option( $option_name );
    if ( ! empty( $stored_options ) ) {
        // ok: claude.php.wordpress.access-control.wp-parse-args-user-wins-wp-query
        $defaults = wp_parse_args( $stored_options, $defaults );
    }
    return $defaults;
}

// Safe: get_option() called directly inline as the first wp_parse_args() arg
// (no intermediate variable) — still a stored plugin-settings value, not
// request-controlled data.
function get_plugin_settings_inline( $defaults ) {
    // ok: claude.php.wordpress.access-control.wp-parse-args-user-wins-wp-query
    $options = wp_parse_args( get_option( 'my_plugin_options' ), $defaults );
    return $options;
}

// Safe: same inline shape with get_site_option().
function get_network_settings_inline( $defaults ) {
    // ok: claude.php.wordpress.access-control.wp-parse-args-user-wins-wp-query
    $options = wp_parse_args( get_site_option( 'my_plugin_network_options', array() ), $defaults );
    return $options;
}

// ── Rule 2 (taint): user input flows directly to WP_Query ────────────────────

// --- Vulnerable patterns ---

// AJAX handler accepts a generic args array and merges with wrong wp_parse_args order.
// Mirrors the D-1 pattern: $user_query_args as first arg wins over post_status default.
function vulnerable_load_more_nopriv() {
    $ajax_args = $_POST['args'];
    $defaults  = array(
        'post_type'   => 'post',
        'post_status' => 'publish',
        'numberposts' => 10,
    );
    $wp_query_args = $ajax_args['wp_query_args'] ?? array();
    $q_args = wp_parse_args( $wp_query_args, $defaults );
    // ruleid: claude.php.wordpress.access-control.wp-query-user-controlled-args
    $query = new WP_Query( $q_args );
    return $query->posts;
}

// REST endpoint passes full request params to get_posts().
function vulnerable_rest_get_posts( WP_REST_Request $request ) {
    $args = $request->get_params();
    // ruleid: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return get_posts( $args );
}

// Generic $_GET array forwarded to query_posts without sanitizing post_status.
function vulnerable_archive_filter() {
    $filters = $_GET['query'];
    $merged  = wp_parse_args( $filters, array( 'post_status' => 'publish' ) );
    // ruleid: claude.php.wordpress.access-control.wp-query-user-controlled-args
    query_posts( $merged );
}

// --- Safe patterns ---

// Each accepted value is sanitized to a scalar; no user-controlled array keys reach WP_Query.
function safe_individual_keys_sanitized() {
    $post_type = sanitize_key( $_POST['post_type'] ?? 'post' );
    $paged     = absint( $_POST['page'] ?? 1 );
    $s         = sanitize_text_field( $_POST['s'] ?? '' );
    $args = array(
        'post_type'   => $post_type,
        'post_status' => 'publish',
        'paged'       => $paged,
        's'           => $s,
    );
    // ok: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return new WP_Query( $args );
}

// Hardcoded args array — no user input flows in; no taint source.
function safe_hardcoded_query() {
    $args = array(
        'post_type'      => 'post',
        'post_status'    => 'publish',
        'posts_per_page' => 10,
        'orderby'        => 'date',
        'order'          => 'DESC',
    );
    // ok: claude.php.wordpress.access-control.wp-query-user-controlled-args
    $query = new WP_Query( $args );
    return $query->posts;
}

// DB-read breaks taint chain; option value is trusted configuration, not user input.
function safe_option_controlled_args() {
    $saved_args = get_option( 'my_plugin_query_args', array() );
    $args = wp_parse_args( $saved_args, array( 'post_status' => 'publish' ) );
    // ok: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return get_posts( $args );
}

// wp_parse_id_list() reduces input to integer array — cannot produce post_status override.
function safe_id_list_to_post_in() {
    $ids  = wp_parse_id_list( $_POST['post_ids'] );
    $args = array( 'post_type' => 'post', 'post_status' => 'publish', 'post__in' => $ids );
    // ok: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return new WP_Query( $args );
}

// post_status hardcoded to 'publish' directly in the literal, alongside an
// UNSANITIZED tainted post_type/orderby value from the same request array — the
// hardcoded key still forces already-public content regardless of the other keys.
// Mirrors happy-elementor-addons 3.22.0 Ajax_Handler::post_tab() (ajax-handler.php:224-240).
function safe_hardcoded_post_status_with_tainted_sibling_key() {
    $settings   = ha_sanitize_array_recursively( $_POST['post_tab_query'] );
    $post_type  = $settings['post_type'];
    $orderby    = $settings['orderby'];
    $order      = $settings['order'];
    $args = [
        'post_status'      => 'publish',
        'post_type'        => $post_type,
        'orderby'          => $orderby,
        'order'            => $order,
        'suppress_filters' => false,
    ];
    // ok: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return get_posts( $args );
}

// post_status hardcoded to a non-'publish' literal ('any') alongside a tainted
// 'p' (single post ID) sibling key: the attacker only selects WHICH post is
// fetched within the already-fixed status scope — the hardcoded literal,
// whatever its value, cannot itself be overridden by this direct-array-literal
// construction shape.
function safe_hardcoded_post_status_any_literal_with_tainted_id() {
    $post_id = isset( $_GET['post'] ) ? $_GET['post'] : $_POST['post_ID'];
    $args = array(
        'post_type'      => 'my_cpt',
        'posts_per_page' => 1,
        'post_status'    => 'any',
        'p'              => $post_id,
    );
    // ok: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return get_posts( $args );
}

// post_status itself is the tainted value (a bare variable, not a quoted
// literal) — must still fire; the metavariable-regex literal-only guard must
// not be mistaken for a general "post_status key present" exemption.
function vulnerable_post_status_itself_tainted() {
    $status = $_GET['status'];
    $args = array(
        'post_type'   => 'post',
        'post_status' => $status,
    );
    // ruleid: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return new WP_Query( $args );
}

// array_merge() shape: a filter-suppliable (potentially tainted) first array
// merged with a hardcoded-defaults second array containing a non-'publish'
// literal post_status plus a tainted single 'p' (post ID) sibling key —
// array_merge() gives the SECOND array's string keys priority, so the
// hardcoded post_status always wins regardless of what the first array (or
// the sibling 'p' key) contains.
function safe_array_merge_hardcoded_post_status_wins( $post_type ) {
    $filter_args = apply_filters( 'my_plugin_get_inquiry_data_args', array() );
    $post_id     = isset( $_GET['post'] ) ? $_GET['post'] : $_POST['post_ID'];
    $args = array_merge(
        $filter_args,
        array(
            'post_type'      => $post_type,
            'posts_per_page' => 1,
            'post_status'    => 'any',
            'p'              => $post_id,
        )
    );
    // ok: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return get_posts( $args );
}

// array_merge() wrong-order shape: the tainted array is the SECOND (winning)
// argument, so its 'post_status' key overrides the hardcoded first array —
// must still fire despite a hardcoded post_status being present in $defaults.
function vulnerable_array_merge_tainted_array_wins() {
    $defaults = array( 'post_type' => 'post', 'post_status' => 'publish' );
    $user_args = $_POST['args'];
    $args = array_merge( $defaults, $user_args );
    // ruleid: claude.php.wordpress.access-control.wp-query-user-controlled-args
    return get_posts( $args );
}
