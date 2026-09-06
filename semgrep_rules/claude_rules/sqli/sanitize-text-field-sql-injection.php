<?php
/**
 * Test cases for sanitize-text-field-sql-injection.yaml
 * Rule id: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
 */

// TP: second-order SQLi — meta_key read from DB, sanitize_text_field applied, interpolated into bulk INSERT via string concat
function tp_second_order_meta_key_string_concat() {
    global $wpdb;
    $new_id   = 42;
    $rows     = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, meta_value FROM {$wpdb->postmeta} WHERE post_id=%d", 1 ) );
    $sql      = "INSERT INTO {$wpdb->postmeta} (post_id, meta_key, meta_value) ";
    foreach ( $rows as $row ) {
        $meta_key  = sanitize_text_field( $row->meta_key );
        $sql      .= "SELECT $new_id, '$meta_key', 'x' UNION ALL ";
    }
    // ruleid: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->query( $sql );
}

// TP: first-order — sanitize_text_field applied to $_POST value, then direct SQL interpolation
function tp_first_order_post_interpolation() {
    global $wpdb;
    $search = sanitize_text_field( $_POST['search'] );
    // ruleid: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_title LIKE '%$search%'" );
}

// TP: sanitize_textarea_field applied to option value, interpolated into WHERE clause
function tp_textarea_field_option_sql() {
    global $wpdb;
    $tag = sanitize_textarea_field( get_option( 'plugin_tag_filter' ) );
    // ruleid: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_row( "SELECT * FROM {$wpdb->terms} WHERE slug = '$tag'" );
}

// TP: sanitize_text_field on GET param, used in ORDER BY (unquoted — SQL function injection)
function tp_orderby_sanitize_text_field() {
    global $wpdb;
    $order = sanitize_text_field( $_GET['orderby'] );
    // ruleid: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $order" );
}

// OK: esc_sql applied after sanitize_text_field — single quotes escaped before interpolation
function ok_esc_sql_applied() {
    global $wpdb;
    $meta_key = esc_sql( sanitize_text_field( $_POST['key'] ) );
    // ok: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_results( "SELECT * FROM {$wpdb->postmeta} WHERE meta_key = '$meta_key'" );
}

// OK: $wpdb->prepare() used — parameterized, no injection possible
function ok_prepare_used() {
    global $wpdb;
    $meta_key = sanitize_text_field( $_POST['key'] );
    // ok: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->postmeta} WHERE meta_key = %s", $meta_key ) );
}

// OK: intval applied after sanitize_text_field — numeric output, no SQL metacharacters
function ok_intval_applied() {
    global $wpdb;
    $id = intval( sanitize_text_field( $_POST['id'] ) );
    // ok: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE ID = $id" );
}

// OK: sanitize_key applied after sanitize_text_field — [a-z0-9_-] only, no SQL metacharacters
function ok_sanitize_key_applied() {
    global $wpdb;
    $key = sanitize_key( sanitize_text_field( $_POST['meta_key'] ) );
    // ok: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_results( "SELECT * FROM {$wpdb->postmeta} WHERE meta_key = '$key'" );
}

// OK: sanitize_text_field wrapping get_var with static string literal — DB metadata, no user input in query
function ok_sanitize_wraps_get_var_literal() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $version = sanitize_text_field( $wpdb->get_var( "SELECT VERSION()" ) );
    return $version;
}

// TP: sanitize_text_field on result of get_var (variable query already executed), then into second query
// The literal-only sanitizer does NOT suppress this because sanitize_text_field receives the
// already-fetched string value, not a nested get_var("literal") call.
function tp_sanitize_on_get_var_result_then_second_query() {
    global $wpdb;
    $user_id = (int) $_POST['uid'];
    $stored_key = $wpdb->get_var( $wpdb->prepare( "SELECT meta_key FROM {$wpdb->usermeta} WHERE user_id = %d LIMIT 1", $user_id ) );
    $meta_key = sanitize_text_field( $stored_key );
    // ruleid: claude.php.wordpress.sqli.sanitize-text-field-sql-injection
    $wpdb->get_results( "SELECT * FROM {$wpdb->postmeta} WHERE meta_key = '$meta_key'" );
}
