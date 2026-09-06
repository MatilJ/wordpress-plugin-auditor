<?php
/**
 * Test cases for wpdb-query-user-input-taint.yaml
 * Rule id: claude.php.wordpress.sqli.wpdb-query-user-input-taint
 */

// TP: raw ORDER BY without any sanitizer
function tp_order_by_raw() {
    global $wpdb;
    $order = $_POST['order'];
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results("SELECT * FROM t ORDER BY $order");
}

// TP: raw WHERE without prepare
function tp_where_raw() {
    global $wpdb;
    $id = $_POST['id'];
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results("SELECT * FROM t WHERE id = '$id'");
}

// OK: sanitize_sql_orderby is now in the sanitizer list
function ok_sanitize_sql_orderby() {
    global $wpdb;
    $order_by = sanitize_sql_orderby($_POST['order_by']);
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results("SELECT * FROM t ORDER BY `$order_by`");
}

// OK: intval cast
function ok_intval() {
    global $wpdb;
    $id = intval($_POST['id']);
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results("SELECT * FROM t WHERE id = $id");
}

// OK: goes through $wpdb->prepare()
function ok_prepare() {
    global $wpdb;
    $id = $_POST['id'];
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE id = %d", $id));
}

// TP: REST API get_param to SQL without prepare
function tp_rest_param_sql( $request ) {
    global $wpdb;
    $id = $request->get_param( 'id' );
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE ID = $id" );
}

// TP: REST API array access to SQL without prepare
function tp_rest_array_sql( $request ) {
    global $wpdb;
    $search = $request['search'];
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_title LIKE '%$search%'" );
}

// TP: REST API get_json_params to SQL without prepare
function tp_rest_json_params_sql( $request ) {
    global $wpdb;
    $params = $request->get_json_params();
    $name = $params['name'];
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_var( "SELECT ID FROM {$wpdb->users} WHERE user_login = '$name'" );
}

// OK: REST API parameter through prepare
function ok_rest_param_prepare( $request ) {
    global $wpdb;
    $id = $request->get_param( 'id' );
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ) );
}

// OK: REST API parameter through intval
function ok_rest_param_intval( $request ) {
    global $wpdb;
    $id = intval( $request->get_param( 'id' ) );
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE ID = $id" );
}

// OK: DateTime constructor — throws on invalid date, format() outputs only date components
function ok_datetime_sanitizer() {
    global $wpdb;
    $start = (new DateTime( $_GET['start_date'] ))->format( 'Y-m-d' );
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_date >= '$start'" );
}

// OK: DateTimeImmutable constructor — same defense as DateTime
function ok_datetimeimmutable_sanitizer() {
    global $wpdb;
    $end = (new DateTimeImmutable( $_POST['end_date'] ))->format( 'Y-m-d' );
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_date <= '$end'" );
}

// TP: $wp_query->get() value interpolated into SQL without prepare
function tp_wp_query_get_sql() {
    global $wpdb, $wp_query;
    $slug = $wp_query->get('location');
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_var("SELECT location_id FROM wp_locations WHERE location_slug='$slug' LIMIT 1");
}

// TP: $wp_query->get() with variable key into get_row
function tp_wp_query_get_var_key() {
    global $wpdb, $wp_query;
    $archetype = $wp_query->get('event_archetype');
    $path = $wp_query->get($archetype);
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_row("SELECT event_id FROM wp_events WHERE event_slug='{$path}' LIMIT 1");
}

// TP: get_query_var() into SQL without prepare
function tp_get_query_var_sql() {
    global $wpdb;
    $slug = get_query_var('event');
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_var("SELECT event_id FROM wp_events WHERE event_slug='$slug' LIMIT 1");
}

// OK: $wp_query->get() through $wpdb->prepare()
function ok_wp_query_prepare() {
    global $wpdb, $wp_query;
    $slug = $wp_query->get('location');
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_var($wpdb->prepare("SELECT location_id FROM wp_locations WHERE location_slug=%s LIMIT 1", $slug));
}

// OK: get_query_var() through esc_sql()
function ok_get_query_var_esc_sql() {
    global $wpdb;
    $slug = esc_sql(get_query_var('event'));
    // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_var("SELECT event_id FROM wp_events WHERE event_slug='$slug' LIMIT 1");
}

// TP: $_COOKIE value found by iterating all cookies (no bracket access — a
// dynamic/hashed cookie name, e.g. wordpress_logged_in_<hash>) interpolated
// into a raw SQL string. CVE-2023-6063 (WP Fastest Cache <=1.2.1) pre-fix shape.
function tp_cookie_foreach_iteration_sql() {
    global $wpdb;
    foreach ((array) $_COOKIE as $cookie_key => $cookie_value) {
        if (preg_match("/wordpress_logged_in/i", $cookie_key)) {
            $username = preg_replace("/^([^\|]+)\|.+/", "$1", $cookie_value);
            break;
        }
    }
    if (isset($username) && $username) {
        // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
        $wpdb->get_var("SELECT ID FROM {$wpdb->users} WHERE user_login = \"$username\"");
    }
}

// TP: direct $_COOKIE[] bracket access interpolated into raw SQL
function tp_cookie_bracket_sql() {
    global $wpdb;
    $session_id = $_COOKIE['session_id'];
    // ruleid: claude.php.wordpress.sqli.wpdb-query-user-input-taint
    $wpdb->get_row("SELECT * FROM {$wpdb->prefix}sessions WHERE session_id = '$session_id'");
}

// OK: same cookie-iteration shape, but through esc_sql() — the real
// CVE-2023-6063 1.2.2 patch (esc_sql() call added immediately before the query).
function ok_cookie_foreach_iteration_esc_sql() {
    global $wpdb;
    foreach ((array) $_COOKIE as $cookie_key => $cookie_value) {
        if (preg_match("/wordpress_logged_in/i", $cookie_key)) {
            $username = preg_replace("/^([^\|]+)\|.+/", "$1", $cookie_value);
            break;
        }
    }
    if (isset($username) && $username) {
        $username = esc_sql($username);
        // ok: claude.php.wordpress.sqli.wpdb-query-user-input-taint
        $wpdb->get_var("SELECT ID FROM {$wpdb->users} WHERE user_login = \"$username\"");
    }
}
