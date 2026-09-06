<?php
/**
 * Test file for claude.php.wordpress.sqli.wpdb-unsafe-in-clause
 *
 * IN() clause injection: implode() of unsanitized array values
 * concatenated directly into $wpdb SQL methods.
 *
 * NOTE: Test cases use plain string literals ("...") not interpolated strings
 * ("...{$wpdb->posts}...") because Semgrep's "..." metapattern only matches
 * PHP plain string nodes, not EncapsedString nodes. In real plugin code,
 * interpolated table names are common — those matches still work because
 * Semgrep matches the concatenation structure, not the string content.
 */

global $wpdb;

// --- TRUE POSITIVES ---

// TP-1: exploded user input directly into IN clause
function tp_explode_in_clause() {
    global $wpdb;
    $ids = explode( ',', $_POST['ids'] );
    // ruleid: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->query( "DELETE FROM tbl WHERE ID IN (" . implode( ',', $ids ) . ")" );
}

// TP-2: user array into get_results IN clause
function tp_user_array_get_results() {
    global $wpdb;
    $user_ids = $_POST['user_ids'];
    // ruleid: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_results( "SELECT * FROM users WHERE ID IN (" . implode( ',', $user_ids ) . ")" );
}

// TP-3: get_var with implode
function tp_get_var_implode() {
    global $wpdb;
    $cat_ids = explode( ',', $_GET['categories'] );
    // ruleid: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_var( "SELECT COUNT(*) FROM posts WHERE post_category IN (" . implode( ',', $cat_ids ) . ")" );
}

// TP-4: implode without trailing string concat (end of query)
function tp_implode_end_of_query() {
    global $wpdb;
    $ids = explode( ',', $_POST['ids'] );
    // ruleid: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_results( "SELECT * FROM posts WHERE ID IN (" . implode( ',', $ids ) );
}

// --- FALSE POSITIVES (OK) ---

// OK-1: array_map intval — integer cast, safe
function ok_array_map_intval() {
    global $wpdb;
    $ids = explode( ',', $_POST['ids'] );
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->query( "DELETE FROM posts WHERE ID IN (" . implode( ',', array_map( 'intval', $ids ) ) . ")" );
}

// OK-2: array_map absint — integer cast, safe
function ok_array_map_absint() {
    global $wpdb;
    $ids = explode( ',', $_POST['ids'] );
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_results( "SELECT * FROM posts WHERE ID IN (" . implode( ',', array_map( 'absint', $ids ) ) . ")" );
}

// OK-3: array_fill placeholder construction — builds '%s,%s,...', not values
function ok_array_fill_placeholders() {
    global $wpdb;
    $ids = explode( ',', $_POST['ids'] );
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_results( "SELECT * FROM posts WHERE ID IN (" . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ")" );
}

// OK-4: wp_parse_id_list — returns array of absint, safe
function ok_wp_parse_id_list() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_results( "SELECT * FROM posts WHERE ID IN (" . implode( ',', wp_parse_id_list( $_POST['ids'] ) ) . ")" );
}

// OK-5: array_map floatval — float cast, safe
function ok_array_map_floatval() {
    global $wpdb;
    $prices = explode( ',', $_POST['prices'] );
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_results( "SELECT * FROM products WHERE price IN (" . implode( ',', array_map( 'floatval', $prices ) ) . ")" );
}

// OK-6: array_map sanitize_key — [a-z0-9_-] only, safe
function ok_array_map_sanitize_key() {
    global $wpdb;
    $slugs = explode( ',', $_POST['slugs'] );
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $wpdb->get_results( "SELECT * FROM posts WHERE post_name IN (" . implode( ',', array_map( 'sanitize_key', $slugs ) ) . ")" );
}

// --- Variant: sprintf()-built "IN (%s)" fragment for a custom ORM/query
// builder raw-fragment method, not a direct $wpdb call. ---

// TP-5: sprintf() IN(%s) fragment, un-cast array, bare implode argument
function tp_sprintf_in_clause_bare() {
    $staff_ids = $_POST['staff_ids'];
    // ruleid: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $where = sprintf( 'staff_id IN (%s)', implode( ',', $staff_ids ) );
    return $where;
}

// TP-6: sprintf() IN(%s) fragment, implode nested in a ternary (the real
// pre-fix shape: "empty() ? 'NULL' : implode(...)" instead of a bare arg)
function tp_sprintf_in_clause_ternary() {
    $staff_ids = $_POST['staff_ids'];
    // ruleid: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $where = sprintf(
        'service_id = %d AND staff_id IN (%s)',
        1,
        empty( $staff_ids ) ? 'NULL' : implode( ',', $staff_ids )
    );
    return $where;
}

// OK-7: sprintf() IN(%s) fragment, array_map intval — integer cast, safe
function ok_sprintf_in_clause_intval() {
    $staff_ids = $_POST['staff_ids'];
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $where = sprintf(
        'service_id = %d AND staff_id IN (%s)',
        1,
        empty( $staff_ids ) ? 'NULL' : implode( ',', array_map( 'intval', $staff_ids ) )
    );
    return $where;
}

// OK-8: sprintf() format string without an IN(%s) shape — unrelated use of
// implode() inside a sprintf(), not a SQL IN() clause
function ok_sprintf_not_in_clause() {
    $names = $_POST['names'];
    // ok: claude.php.wordpress.sqli.wpdb-unsafe-in-clause
    $label = sprintf( 'Selected: %s', implode( ', ', $names ) );
    return $label;
}
