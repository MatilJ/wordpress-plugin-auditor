<?php
// Test cases for claude.php.wordpress.sqli.sprintf-sql-build

function get_row_inline_sprintf( $stored_value ) {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.sprintf-sql-build
    return $wpdb->get_results( sprintf( "SELECT * FROM t WHERE val = '%s'", $stored_value ) );
}

// sprintf() result assigned to a variable, then that variable spliced via
// curly-brace interpolation into a separately-built query string one or
// more statements later — the sprintf() call is not itself the query text.
// NOTE: taint-mode findings are reported at the SINK, not the source — the
// ruleid annotation goes on the line before the sink call, not the sprintf().
function legacy_locator_query( $args ) {
    global $wpdb;
    $by_shortcode_atts = '';
    if ( isset( $args['shortcode_atts'] ) ) {
        $by_shortcode_atts = sprintf( "AND shortcode_atts = '%s'", $args['shortcode_atts'] );
    }
    // ruleid: claude.php.wordpress.sqli.sprintf-sql-build
    $results = $wpdb->get_results( "SELECT * FROM t WHERE 1=1 {$by_shortcode_atts} LIMIT 10", ARRAY_A );
    return $results;
}

// Same assign-then-splice idiom via '.' concatenation instead of curly
// interpolation.
function get_row_concat_sprintf( $stored_value ) {
    global $wpdb;
    $frag = sprintf( "AND val = '%s'", $stored_value );
    $sql  = "SELECT * FROM t WHERE 1=1 " . $frag;
    // ruleid: claude.php.wordpress.sqli.sprintf-sql-build
    return $wpdb->get_results( $sql );
}

function get_row_prepared( $stored_value ) {
    global $wpdb;
    $frag = sprintf( "AND val = %s", '%s' );
    $sql  = $wpdb->prepare( "SELECT * FROM t WHERE 1=1 " . $frag, $stored_value );
    // ok: claude.php.wordpress.sqli.sprintf-sql-build
    return $wpdb->get_results( $sql );
}

// The rule intentionally does not auto-clear taint just because a %d
// specifier is used — per its own triage guidance, a human must still
// confirm the bound argument is verified numeric, so this is a ruleid, not
// an ok, case.
function get_row_int_only( $numeric_id ) {
    global $wpdb;
    $frag = sprintf( "AND id = %d", (int) $numeric_id );
    // ruleid: claude.php.wordpress.sqli.sprintf-sql-build
    return $wpdb->get_results( "SELECT * FROM t WHERE 1=1 " . $frag );
}
