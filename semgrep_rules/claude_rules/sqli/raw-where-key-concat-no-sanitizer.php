<?php

function db_where_conditions( $args ) {
	global $wpdb;
	$where = '';
	if ( ! empty( $args['append_where_sql'] ) ) {
		if ( ! is_array( $args['append_where_sql'] ) ) {
			$args['append_where_sql'] = array( $args['append_where_sql'] );
		}
		// ruleid: claude.php.wordpress.sqli.raw-where-key-concat-no-sanitizer
		foreach ( $args['append_where_sql'] as $where_sql ) {
			$where .= $where_sql;
		}
	}
	return $where;
}

function build_conditions( $args ) {
	$where = ' WHERE 1=1';
	if ( ! empty( $args['raw_where'] ) ) {
		// ruleid: claude.php.wordpress.sqli.raw-where-key-concat-no-sanitizer
		$where .= $args['raw_where'];
	}
	return $where;
}

// ok: claude.php.wordpress.sqli.raw-where-key-concat-no-sanitizer
function db_where_conditions_patched( $args ) {
	global $wpdb;
	$where = '';
	// Fix: reject the same key when it arrives directly from the request —
	// only a trusted, code-level caller may still supply it.
	if ( ! empty( $args['append_where_sql'] ) && empty( $_REQUEST['append_where_sql'] ) ) {
		if ( ! is_array( $args['append_where_sql'] ) ) {
			$args['append_where_sql'] = array( $args['append_where_sql'] );
		}
		foreach ( $args['append_where_sql'] as $where_sql ) {
			$where .= $where_sql;
		}
	}
	return $where;
}

// ok: claude.php.wordpress.sqli.raw-where-key-concat-no-sanitizer
function build_conditions_prepared( $args, $wpdb ) {
	$where = ' WHERE 1=1';
	if ( ! empty( $args['status'] ) ) {
		$where .= $wpdb->prepare( ' AND status = %s', $args['status'] );
	}
	return $where;
}
