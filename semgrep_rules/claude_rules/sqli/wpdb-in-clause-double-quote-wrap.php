<?php
/**
 * Test file for claude.php.wordpress.sqli.wpdb-in-clause-double-quote-wrap
 *
 * A CSV IN() list already quoted/escaped per element by a helper is re-wrapped in
 * an extra, redundant pair of literal single quotes when concatenated into a raw
 * $wpdb query string, defeating the per-element escaping (CWE-89).
 */

global $wpdb;

// --- TRUE POSITIVES ---

// TP-1: get_results — helper-quoted list re-wrapped in an extra quote pair
function tp_get_results_double_quote_wrap() {
	global $wpdb;
	$ids  = maybe_unserialize( $_POST['answer_ids'] );
	$list = QueryHelper::prepare_in_clause( (array) $ids );
	// ruleid: claude.php.wordpress.sqli.wpdb-in-clause-double-quote-wrap
	$results = $wpdb->get_results( "SELECT title FROM tbl WHERE id IN ('" . $list . "')" );
}

// TP-2: query() — same anti-pattern, different table/variable names
function tp_query_double_quote_wrap() {
	global $wpdb;
	$codes = $_POST['codes'];
	$list  = implode( ',', array_map( fn( $v ) => $wpdb->prepare( '%s', $v ), (array) $codes ) );
	// ruleid: claude.php.wordpress.sqli.wpdb-in-clause-double-quote-wrap
	$wpdb->query( "DELETE FROM coupons WHERE code IN ('" . $list . "')" );
}

// --- FALSE POSITIVES (OK) ---

// OK-1: fix shape — list interpolated without the extra surrounding quotes
function ok_no_extra_quote_wrap() {
	global $wpdb;
	$ids  = array_filter( array_map( 'absint', (array) $_POST['answer_ids'] ) );
	$list = QueryHelper::prepare_in_clause( $ids );
	// ok: claude.php.wordpress.sqli.wpdb-in-clause-double-quote-wrap
	$results = $wpdb->get_results( "SELECT title FROM tbl WHERE id IN ({$list})" );
}

// OK-2: integer-cast list even with the same edge quotes — cannot carry injected chars
function ok_absint_cast_list() {
	global $wpdb;
	$ids = explode( ',', $_POST['ids'] );
	// ok: claude.php.wordpress.sqli.wpdb-in-clause-double-quote-wrap
	$wpdb->query( "DELETE FROM tbl WHERE id IN ('" . implode( ',', array_map( 'absint', $ids ) ) . "')" );
}

// OK-3: standard WP DB-read pattern unrelated to IN-clause building
function ok_plain_prepared_read() {
	global $wpdb;
	$id = absint( $_GET['id'] );
	// ok: claude.php.wordpress.sqli.wpdb-in-clause-double-quote-wrap
	$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM tbl WHERE id = %d", $id ) );
}
