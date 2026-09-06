<?php
// Test file for lfi exploded-segments-template-path-no-basename rule

// Real pre-fix shape: a feed/type parameter is exploded into segments,
// segments are rebuilt into candidate template filenames with no
// per-segment sanitizer, and the collector is handed to locate_template()
// then, on the fallback path, to load_template() guarded only by
// file_exists() (does not constrain the path to the intended directory).
function xmlsf_bad_load_template( $is_comment_feed, $feed ) {
	$parts = explode( '-', $feed, 3 );

	$templates = array();
	if ( ! empty( $parts[1] ) ) {
		if ( ! empty( $parts[2] ) ) {
			$templates[] = "{$parts[0]}-{$parts[1]}-{$parts[2]}.php";
		}
		$templates[] = "{$parts[0]}-{$parts[1]}.php";
	} else {
		$templates[] = "{$parts[0]}.php";
	}

	locate_template( $templates, true );

	$template = PLUGIN_DIR . '/views/feed-' . implode( '-', array_slice( $parts, 0, 2 ) ) . '.php';
	if ( file_exists( $template ) ) {
		// ruleid: claude.php.wordpress.lfi.exploded-segments-template-path-no-basename
		load_template( $template );
	}
}

// Simpler shape: split directly on a slug, single collector variable,
// straight into get_template_part() with no intermediate array.
function bad_get_template_part( $slug ) {
	$parts = explode( '/', $slug, 2 );
	$path = $parts[0] . '/' . $parts[1];
	// ruleid: claude.php.wordpress.lfi.exploded-segments-template-path-no-basename
	get_template_part( $path );
}

// Fixed shape (the actual patch): every exploded segment is run through
// basename() before being reassembled, stripping any '/' or '..'
// sequences a segment could otherwise carry.
function xmlsf_good_load_template( $is_comment_feed, $feed ) {
	$parts = array();
	foreach ( explode( '-', $feed, 3 ) as $part ) {
		$parts[] = basename( $part );
	}

	$templates = array();
	if ( ! empty( $parts[1] ) ) {
		if ( ! empty( $parts[2] ) ) {
			// ok: claude.php.wordpress.lfi.exploded-segments-template-path-no-basename
			$templates[] = "{$parts[0]}-{$parts[1]}-{$parts[2]}.php";
		}
		$templates[] = "{$parts[0]}-{$parts[1]}.php";
	} else {
		$templates[] = "{$parts[0]}.php";
	}

	locate_template( $templates, true );
}

// Alternate fix shape: every exploded segment is run through basename()
// in a loop (rather than the array-literal foreach the patch itself
// used), so no '/' or '..' can survive into the assembled path.
function good_get_template_part( $slug ) {
	$raw   = explode( '/', $slug, 2 );
	$parts = array();
	foreach ( $raw as $segment ) {
		$parts[] = basename( $segment );
	}
	$path = $parts[0] . '/' . $parts[1];
	// ok: claude.php.wordpress.lfi.exploded-segments-template-path-no-basename
	get_template_part( $path );
}

// Fix applied at the sink, on the same scalar-concat shape that fires
// above (bad_get_template_part) without it: basename() wraps the
// assembled path immediately before get_template_part().
function good_basename_at_sink( $slug ) {
	$parts = explode( '/', $slug, 2 );
	$path  = basename( $parts[0] . '/' . $parts[1] );
	// ok: claude.php.wordpress.lfi.exploded-segments-template-path-no-basename
	get_template_part( $path );
}

// Unrelated shape: explode() is used to build a list of tag names for
// display, never reaching an include/require/template-loading sink.
function good_unrelated_explode( $csv ) {
	$tags = explode( ',', $csv );
	$out  = array();
	foreach ( $tags as $tag ) {
		$out[] = esc_html( $tag );
	}
	// ok: claude.php.wordpress.lfi.exploded-segments-template-path-no-basename
	return implode( ', ', $out );
}
