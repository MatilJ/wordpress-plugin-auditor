<?php
// sql-keyword-blocklist-array-iteration rule test cases

// ── VULNERABLE PATTERNS ──────────────────────────────────────────────────────

function prepare_search_input( $search ) {
	$search = trim( sanitize_text_field( wp_unslash( $search ) ) );

	// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-array-iteration
	$regexp_map = array(
		'/select(.*?)from/im',
		'/select(.*?)sleep/im',
		'/select(.*?)database/im',
		'/select(.*?)where/im',
		'/update(.*?)set/im',
		'/delete(.*?)from/im',
	);

	foreach ( $regexp_map as $regexp ) {
		preg_match( $regexp, $search, $matches );
		if ( ! empty( $matches ) ) {
			$search = '';
			break;
		}
	}

	return esc_sql( $search );
}

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-array-iteration
$denylist = array( '/union(.*?)select/im', '/insert(.*?)into/im' );
foreach ( $denylist as $pattern ) {
	if ( preg_match( $pattern, $user_input ) ) {
		wp_die( 'Invalid input' );
	}
}

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-array-iteration
$blocked_patterns = [ '/delete(.*?)from/im', '/drop(.*?)table/im' ];
foreach ( $blocked_patterns as $blocked_regex ) {
	preg_match( $blocked_regex, $filter_value, $m );
}


// ── SAFE PATTERNS ────────────────────────────────────────────────────────────

// ok: claude.php.wordpress.sqli.sql-keyword-blocklist-array-iteration
$allowed_sort_fields = array( 'user_login', 'user_email', 'display_name' );
if ( in_array( $sortby, $allowed_sort_fields, true ) ) {
	$query_args['orderby'] = $sortby;
}

// ok: claude.php.wordpress.sqli.sql-keyword-blocklist-array-iteration
$validation_patterns = array( '/^[a-z0-9_-]+$/i', '/^\d+$/' );
foreach ( $validation_patterns as $regex ) {
	if ( preg_match( $regex, $slug ) ) {
		$valid = true;
	}
}

// ok: claude.php.wordpress.sqli.sql-keyword-blocklist-array-iteration
function get_user_by_search( $search ) {
	global $wpdb;
	$like = '%' . $wpdb->esc_like( $search ) . '%';
	return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->users} WHERE user_login LIKE %s", $like ) );
}
