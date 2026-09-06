<?php
/**
 * Test file for
 * claude.php.wordpress.sqli.unvalidated-request-fields-select-column-list
 *
 * A request-controlled "fields"/"columns" array is imploded and interpolated,
 * unquoted, directly into the SELECT column-list position of a query reaching
 * a $wpdb execution method, with no allow-list validation against the real
 * schema or a hardcoded column list (CWE-89). Column/field-name identifier
 * position injection — distinct from value-position SQLi.
 */

// --- TRUE POSITIVES ---

// TP-1: the real pre-fix CVE shape — fields array read from $_GET, each
// element run through an ineffective per-character regex (strips letters/
// underscores instead of SQL metacharacters) and backtick-wrapped, imploded,
// then handed to $wpdb->prepare() with no placeholder arguments at all (a
// no-op call providing zero protection) before the resulting statement is
// executed.
function tp_markers_rest_get( $table ) {
	global $wpdb;

	$fields = null;
	if ( isset( $_GET['fields'] ) && is_string( $_GET['fields'] ) ) {
		$fields = explode( ',', $_GET['fields'] );
	}

	if ( ! empty( $fields ) ) {
		foreach ( $fields as $key => $value ) {
			$fields[ $key ] = '`' . preg_replace( '/[a-z_]/i', '', $value ) . '`';
		}
		$imploded = implode( ',', $fields );

		// ruleid: claude.php.wordpress.sqli.unvalidated-request-fields-select-column-list
		$stmt = $wpdb->prepare( "SELECT $imploded FROM $table" );
		return $wpdb->get_results( $stmt );
	}
}

// TP-2: generalized variant — a REST request parameter's "columns" value is
// imploded and passed straight (no intermediate variable, no prepare() at
// all) to $wpdb->get_results(), with no allow-list check anywhere.
function tp_rest_param_direct( $request ) {
	global $wpdb;

	$columns = explode( ',', $request->get_param( 'columns' ) );
	$select  = implode( ',', $columns );

	// ruleid: claude.php.wordpress.sqli.unvalidated-request-fields-select-column-list
	return $wpdb->get_results( "SELECT $select FROM {$wpdb->prefix}widgets" );
}

// --- FALSE POSITIVES (OK) ---

// OK-1: the actual CVE fix shape — each requested field name is checked
// against the live table schema (SHOW COLUMNS) before being used anywhere,
// so only real, existing column names ever reach the query.
function ok_schema_whitelist_validated( $fields, $table ) {
	global $wpdb;

	$whitelist = $wpdb->get_col( "SHOW COLUMNS FROM $table" );
	$safe      = array();

	foreach ( $fields as $name ) {
		if ( array_search( $name, $whitelist ) !== false ) {
			$safe[] = $name;
		}
	}

	$imploded = implode( ',', $safe );
	// ok: claude.php.wordpress.sqli.unvalidated-request-fields-select-column-list
	$stmt = $wpdb->prepare( "SELECT $imploded FROM $table" );
	return $wpdb->get_results( $stmt );
}

// OK-2: hardcoded allow-list variant — every element is checked against a
// fixed, developer-defined column list with in_array() before the implode.
function ok_hardcoded_allowlist( $fields, $table ) {
	global $wpdb;

	$allowed = array( 'id', 'lat', 'lng', 'address' );
	$safe    = array();

	foreach ( $fields as $name ) {
		if ( in_array( $name, $allowed, true ) ) {
			$safe[] = $name;
		}
	}

	$imploded = implode( ',', $safe );
	// ok: claude.php.wordpress.sqli.unvalidated-request-fields-select-column-list
	return $wpdb->get_results( "SELECT $imploded FROM $table" );
}

// OK-3: standard WP DB-read pattern — no dynamic column list at all, plain
// %d-bound value-position placeholder.
function ok_plain_prepared_read( $id ) {
	global $wpdb;

	// ok: claude.php.wordpress.sqli.unvalidated-request-fields-select-column-list
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ) );
}
