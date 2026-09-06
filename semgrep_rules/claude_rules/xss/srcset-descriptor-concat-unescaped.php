<?php
// Test cases for claude.php.wordpress.xss.srcset-descriptor-concat-unescaped

// ── Vulnerable cases (should MATCH) ──────────────────────────────────────────

function add_missing_srcset_attributes_test( $optimized_url, $descriptor ) {
	$new_srcset_entries = [];
	// ruleid: claude.php.wordpress.xss.srcset-descriptor-concat-unescaped
	$new_srcset_entries[] = $optimized_url . ' ' . $descriptor;
	return $new_srcset_entries;
}

function build_srcset_entry_desc_only_escaped( $url, $descriptor ) {
	// URL side is escaped but the descriptor side is not — still vulnerable.
	$entries_srcset = [];
	// ruleid: claude.php.wordpress.xss.srcset-descriptor-concat-unescaped
	$entries_srcset[] = esc_url( $url ) . ' ' . $descriptor;
	return $entries_srcset;
}

function build_srcset_entry_url_only_escaping_missing( $url, $descriptor ) {
	// Descriptor side is escaped but the URL side is not — still vulnerable.
	$srcset_list = [];
	// ruleid: claude.php.wordpress.xss.srcset-descriptor-concat-unescaped
	$srcset_list[] = $url . ' ' . esc_attr( $descriptor );
	return $srcset_list;
}

// ── Safe cases (should NOT match) ────────────────────────────────────────────

function add_missing_srcset_attributes_fixed( $optimized_url, $descriptor ) {
	$new_srcset_entries = [];
	$escaped_url = esc_url( $optimized_url );
	if ( empty( $escaped_url ) ) {
		return $new_srcset_entries;
	}
	// ok: claude.php.wordpress.xss.srcset-descriptor-concat-unescaped
	$new_srcset_entries[] = $escaped_url . ' ' . esc_attr( $descriptor );
	return $new_srcset_entries;
}

function build_srcset_entry_both_escaped_inline( $url, $descriptor ) {
	$entries_srcset = [];
	// ok: claude.php.wordpress.xss.srcset-descriptor-concat-unescaped
	$entries_srcset[] = esc_url( $url ) . ' ' . esc_attr( $descriptor );
	return $entries_srcset;
}

function unrelated_array_build_no_srcset_name( $url, $descriptor ) {
	global $wpdb;
	// Same shape, but the destination array is not srcset-related — not this
	// rule's concern (e.g. building a log or CSV row from wpdb-read fields).
	$log_rows = [];
	// ok: claude.php.wordpress.xss.srcset-descriptor-concat-unescaped
	$log_rows[] = $url . ' ' . $descriptor;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}log_rows" );
}
