<?php
/**
 * Test file for claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
 *
 * ORDER BY injection via false sanitizers: esc_sql(), sanitize_text_field(),
 * esc_attr() do NOT prevent ORDER BY injection.
 */

global $wpdb;

// --- TRUE POSITIVES ---

// TP-1: esc_sql on orderby — esc_sql escapes quotes but ORDER BY doesn't use quotes
function tp_esc_sql_orderby() {
    global $wpdb;
    $orderby = esc_sql( $_GET['orderby'] );
    // ruleid: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $orderby" );
}

// TP-2: sanitize_text_field on orderby — strips HTML only, SQL operators pass through
function tp_sanitize_text_field_orderby() {
    global $wpdb;
    $orderby = sanitize_text_field( $_GET['orderby'] );
    // ruleid: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $orderby" );
}

// TP-3: esc_attr on order direction — HTML encoding only, no SQL protection
function tp_esc_attr_order() {
    global $wpdb;
    $order = esc_attr( $_GET['order'] );
    // ruleid: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->query( "SELECT * FROM {$wpdb->posts} ORDER BY post_date $order" );
}

// TP-4: sanitize_text_field + wp_unslash — removes addslashes protection too
function tp_sanitize_unslash_orderby() {
    global $wpdb;
    $orderby = sanitize_text_field( wp_unslash( $_REQUEST['orderby'] ) );
    // ruleid: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}custom ORDER BY $orderby DESC" );
}

// TP-5: esc_sql on order direction via get_results
function tp_esc_sql_order_direction() {
    global $wpdb;
    $order = esc_sql( $_POST['order'] );
    // ruleid: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY id $order" );
}

// TP-6: REST API parameter with esc_sql — still unsafe for ORDER BY
function tp_rest_esc_sql_orderby( $request ) {
    global $wpdb;
    $orderby = esc_sql( $request->get_param( 'orderby' ) );
    // ruleid: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $orderby" );
}

// TP-7: Raw superglobal through get_var
function tp_raw_orderby_get_var() {
    global $wpdb;
    $col = $_GET['sort'];
    // ruleid: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts} ORDER BY $col LIMIT 1" );
}

// --- FALSE POSITIVES (OK) ---

// OK-1: sanitize_sql_orderby — regex [a-z0-9_] + ASC/DESC only
function ok_sanitize_sql_orderby() {
    global $wpdb;
    $orderby = sanitize_sql_orderby( $_GET['orderby'] );
    if ( $orderby ) {
        // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
        $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $orderby" );
    }
}

// NOTE: Allowlist via in_array() is a valid runtime defense, but Semgrep taint
// mode cannot track branch-level guards (if (in_array(...)) does not sanitize
// the variable, it controls flow). This fires as a TP in Semgrep but should be
// triaged as FP by the auditor. Not included as a test case.

// OK-2: prepare() with %i identifier placeholder (WP 6.2+)
// NOTE: prepare() is the sanitizer here — the taint chain is $_GET -> prepare() (sanitizer) -> get_results()
function ok_prepare_identifier() {
    global $wpdb;
    $orderby = $_GET['orderby'];
    // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} ORDER BY %i", $orderby ) );
}

// OK-3: sanitize_key — [a-z0-9_-] only
function ok_sanitize_key() {
    global $wpdb;
    $orderby = sanitize_key( $_GET['orderby'] );
    // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $orderby" );
}

// OK-4: intval cast — numeric only
function ok_intval_order() {
    global $wpdb;
    $limit = intval( $_GET['limit'] );
    // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY id LIMIT $limit" );
}

// OK-5: absint cast
function ok_absint_limit() {
    global $wpdb;
    $offset = absint( $_GET['offset'] );
    // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY id LIMIT 10 OFFSET $offset" );
}

// OK-6: (int) cast
function ok_int_cast() {
    global $wpdb;
    $limit = (int) $_GET['limit'];
    // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY id LIMIT $limit" );
}

// OK-7: sanitize_title — [a-z0-9%-_] only
function ok_sanitize_title() {
    global $wpdb;
    $orderby = sanitize_title( $_GET['orderby'] );
    // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} ORDER BY $orderby" );
}

// OK-8: DateTime constructor — throws on invalid date, format() outputs only date components
function ok_datetime_order_limit() {
    global $wpdb;
    $date = (new DateTime( $_GET['date'] ))->format( 'Y-m-d' );
    // ok: claude.php.wordpress.sqli.wpdb-orderby-unsafe-sanitizer
    $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_date = '$date' ORDER BY id" );
}
