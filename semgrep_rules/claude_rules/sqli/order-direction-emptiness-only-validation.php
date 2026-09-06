<?php
// Vulnerable: isset()/else-default shape, direction validated for emptiness
// only (no ASC/DESC allow-list) -- the exact shape of CVE-2026-2495.
function get_boards_route( $req ) {
	// ruleid: claude.php.wordpress.sqli.order-direction-emptiness-only-validation
	if ( isset( $req['order'] ) ) {
		// ruleid: claude.php.wordpress.sqli.order-direction-emptiness-only-validation
		$order = (string) $req['order'];
		if ( empty( $order ) ) {
			return new WP_Error( 403, 'Invalid order passed.' );
		}
	} else {
		$order = 'asc';
	}
	return $order;
}

// Vulnerable: unconditional-cast + empty-only-check shape, different key
// name (sort_order), no isset()/else wrapper.
function get_items_route( $request ) {
	// ruleid: claude.php.wordpress.sqli.order-direction-emptiness-only-validation
	$sort_order = (string) $request['sort_order'];
	if ( empty( $sort_order ) ) {
		return new WP_Error( 403, 'Invalid sort passed.' );
	}
	return $sort_order;
}

// Fixed: the official patch shape -- strtoupper() + strict in_array()
// allow-list against the two legal SQL keywords, no more empty()-only check.
function get_boards_route_fixed( $req ) {
	// ok: claude.php.wordpress.sqli.order-direction-emptiness-only-validation
	if ( isset( $req['order'] ) ) {
		$order = strtoupper( (string) $req['order'] );
		if ( ! in_array( $order, array( 'ASC', 'DESC' ), true ) ) {
			return new WP_Error( 403, 'Invalid order passed.' );
		}
	} else {
		$order = 'ASC';
	}
	return $order;
}

// Fixed: emptiness check still present (legacy default-fallback) but a
// real ASC/DESC allow-list also guards the value later in the same
// function -- the FP guard must recognize this as patched.
function get_items_route_fixed( $request ) {
	// ok: claude.php.wordpress.sqli.order-direction-emptiness-only-validation
	$direction = (string) $request['direction'];
	if ( empty( $direction ) ) {
		$direction = 'asc';
	}
	if ( ! in_array( strtoupper( $direction ), array( 'ASC', 'DESC' ), true ) ) {
		$direction = 'ASC';
	}
	return $direction;
}
