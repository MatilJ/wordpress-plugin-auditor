<?php
/**
 * Test file for claude.php.wordpress.sqli.raw-sql-clause-quoted-variable-interpolation
 *
 * A raw SQL clause fragment (JOIN/WHERE/SELECT/FROM-shaped) is built by direct
 * string interpolation of another variable inside single quotes ('$VAR'),
 * instead of $wpdb->prepare() with a placeholder or esc_sql(). Seeded from
 * CVE-2026-2413 (Ally – Web Accessibility & Usability <= 4.0.3), an
 * unauthenticated SQL injection via the current page's URL path (CWE-89).
 */

// --- TRUE POSITIVES ---

// TP-1: real CVE-2026-2413 shape — LEFT JOIN clause built with a raw
// interpolated URL-path-derived variable, handed to a custom ORM wrapper.
function tp_join_clause_url_path( string $url ) : array {
	$excluded_table = "wp_excluded_pages";
	$remediation_table = "wp_remediations";
	// ruleid: claude.php.wordpress.sqli.raw-sql-clause-quoted-variable-interpolation
	$join = "LEFT JOIN $excluded_table ON $remediation_table.id = $excluded_table.remediation_id AND $excluded_table.page_url = '$url'";
	return Remediation_Table::select( "$remediation_table.*", [], null, null, $join );
}

// TP-2: WHERE clause appended with .=, from a REST parameter.
function tp_where_clause_appended( $request ) {
	global $wpdb;
	$status = $request->get_param( 'status' );
	$where = "";
	// ruleid: claude.php.wordpress.sqli.raw-sql-clause-quoted-variable-interpolation
	$where .= "WHERE post_status = '$status'";
	return $wpdb->get_results( "SELECT * FROM {$wpdb->posts} $where" );
}

// --- FALSE POSITIVES (OK) ---

// OK-1: the actual CVE-2026-2413 fix — $wpdb->prepare() with a %s
// placeholder instead of a raw interpolated single-quoted variable.
function ok_join_clause_prepared( string $url ) : array {
	$excluded_table = "wp_excluded_pages";
	$remediation_table = "wp_remediations";
	// ok: claude.php.wordpress.sqli.raw-sql-clause-quoted-variable-interpolation
	$join = Remediation_Table::db()->prepare(
		"LEFT JOIN $excluded_table ON $remediation_table.id = $excluded_table.remediation_id AND $excluded_table.page_url = %s",
		$url
	);
	return Remediation_Table::select( "$remediation_table.*", [], null, null, $join );
}

// OK-2: standard WP DB-read pattern — no raw quoted-variable SQL fragment at all.
function ok_plain_prepared_read() {
	global $wpdb;
	$id = absint( $_GET['id'] );
	// ok: claude.php.wordpress.sqli.raw-sql-clause-quoted-variable-interpolation
	$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ) );
}

// OK-3: unrelated string assignment with a quoted variable — no SQL keyword present.
function ok_unrelated_string_interpolation( $name ) {
	// ok: claude.php.wordpress.sqli.raw-sql-clause-quoted-variable-interpolation
	$greeting = "Hello, '$name', welcome back!";
	return $greeting;
}
