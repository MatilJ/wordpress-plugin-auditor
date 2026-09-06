<?php
/**
 * Test file for claude.php.wordpress.sqli.orderby-foreach-key-value-allowlist-confusion
 *
 * Key-vs-value confusion in an ORDER BY / GROUP BY allow-list helper: a
 * sibling elseif branch checks array_key_exists() on the loop KEY against
 * the same allow-list array used for an in_array() VALUE check, without
 * rejecting numeric keys first.
 */

global $wpdb;

// --- TRUE POSITIVES ---

// TP-1: generalized shape of the real vulnerable helper (list-style allow-list
// array built from array_keys(), so any small integer key exists in it).
function tp_build_orderby_fields( $orderby_input, $allowed_columns ) {
    $sort_fields = array();
    foreach ( $orderby_input as $key => $value ) {
        // ruleid: claude.php.wordpress.sqli.orderby-foreach-key-value-allowlist-confusion
        if ( in_array( $value, $allowed_columns ) ) {
            $sort_fields[] = $value;
        } elseif ( array_key_exists( $key, $allowed_columns ) ) {
            $sort_fields[] = $value;
        } else {
            unset( $sort_fields[ $key ] );
        }
    }
    return $sort_fields;
}

// TP-2: different variable/function names, GROUP BY builder variant, showing
// the pattern recurs independent of naming.
function tp_sanitize_groupby_columns( $requested, $valid_columns ) {
    $group_by = array();
    foreach ( $requested as $idx => $col ) {
        // ruleid: claude.php.wordpress.sqli.orderby-foreach-key-value-allowlist-confusion
        if ( in_array( $col, $valid_columns ) ) {
            $group_by[] = $col;
        } elseif ( array_key_exists( $idx, $valid_columns ) ) {
            $group_by[] = $col;
        }
    }
    return $group_by;
}

// --- FALSE POSITIVES (OK) ---

// OK-1: the real fix — numeric keys are rejected before the key-based branch
// is allowed to treat $key as a legitimate associative shortcut lookup.
function ok_patched_build_orderby_fields( $orderby_input, $allowed_columns ) {
    $sort_fields = array();
    foreach ( $orderby_input as $key => $value ) {
        // ok: claude.php.wordpress.sqli.orderby-foreach-key-value-allowlist-confusion
        if ( in_array( $value, $allowed_columns ) ) {
            $sort_fields[] = $value;
        } elseif ( !is_numeric( $key ) && array_key_exists( $key, $allowed_columns ) ) {
            $sort_fields[] = $value;
        }
    }
    return $sort_fields;
}

// OK-2: value-only allow-list validation with no key-based fallback branch at
// all — the standard, safe WP DB-read pattern for building an ORDER BY list.
function ok_value_only_orderby( $orderby_input, $allowed_columns ) {
    $sort_fields = array();
    foreach ( $orderby_input as $key => $value ) {
        // ok: claude.php.wordpress.sqli.orderby-foreach-key-value-allowlist-confusion
        if ( in_array( $value, $allowed_columns, true ) ) {
            $sort_fields[] = $value;
        }
    }
    $orderby_sql = ( count( $sort_fields ) > 0 ) ? 'ORDER BY ' . implode( ', ', $sort_fields ) : '';
    return $wpdb->get_results( "SELECT * FROM {$wpdb->posts} $orderby_sql" );
}
