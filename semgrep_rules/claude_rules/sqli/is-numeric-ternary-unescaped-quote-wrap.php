<?php
/**
 * Test file for claude.php.wordpress.sqli.is-numeric-ternary-unescaped-quote-wrap
 *
 * A custom WHERE-clause value builder quotes a value using only an
 * is_numeric() ternary: numeric values pass through bare, anything else is
 * wrapped in a literal pair of single quotes with no escaping applied.
 * Seeded from CVE-2025-13673 (Tutor LMS <= 3.9.6), an unauthenticated SQL
 * injection via the 'coupon_code' checkout parameter (CWE-89).
 */

// --- TRUE POSITIVES ---

// TP-1: real CVE-2025-13673 shape — default WHERE-clause equality branch of
// a custom query-builder helper (QueryHelper::prepare_where_clause()).
function tp_default_equality_branch( $field, $value ) {
	// ruleid: claude.php.wordpress.sqli.is-numeric-ternary-unescaped-quote-wrap
	$value  = is_numeric( $value ) ? $value : "'" . $value . "'";
	$clause = array( $field, '=', $value );
	return $clause;
}

// TP-2: same idiom with the condition/branches reversed (!is_numeric() ...
// quoted : bare), the other ordering seen across this helper's call sites.
function tp_reversed_condition( $val ) {
	// ruleid: claude.php.wordpress.sqli.is-numeric-ternary-unescaped-quote-wrap
	$val1 = ! is_numeric( $val ) ? "'" . $val . "'" : $val;
	return $val1;
}

// --- FALSE POSITIVES (OK) ---

// OK-1: the actual CVE-2025-13673 fix — the value is routed through
// $wpdb->prepare() with a %s/%d placeholder instead of a manual quote-wrap.
function ok_prepare_value( $value ) {
	global $wpdb;
	// ok: claude.php.wordpress.sqli.is-numeric-ternary-unescaped-quote-wrap
	$escaped_value = is_int( $value ) ? $wpdb->prepare( '%d', $value ) : $wpdb->prepare( '%s', $value );
	return $escaped_value;
}

// OK-2: quoted branch escapes the value with esc_sql() before wrapping —
// safe because it is no longer the bare value being quoted.
function ok_esc_sql_before_wrap( $value ) {
	// ok: claude.php.wordpress.sqli.is-numeric-ternary-unescaped-quote-wrap
	$value = is_numeric( $value ) ? $value : "'" . esc_sql( $value ) . "'";
	return $value;
}

// OK-3: standard WP DB-read pattern — no ternary quote-wrap at all.
function ok_plain_prepared_read() {
	global $wpdb;
	$id = absint( $_GET['id'] );
	// ok: claude.php.wordpress.sqli.is-numeric-ternary-unescaped-quote-wrap
	$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ) );
	return $row;
}
