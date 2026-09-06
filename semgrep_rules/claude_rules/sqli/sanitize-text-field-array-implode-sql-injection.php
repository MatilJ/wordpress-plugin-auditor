<?php
/**
 * Test cases for sanitize-text-field-array-implode-sql-injection.yaml
 * Rule id: claude.php.wordpress.sqli.sanitize-text-field-array-implode-sql-injection
 *
 * NOTE: This rule detects implode() directly in $wpdb->query() argument expressions.
 * The pattern $sql .= implode(...); $wpdb->query($sql) is NOT caught here (Semgrep
 * PHP taint does not handle .= compound assignment in multi-statement patterns).
 */

// TP: implode() directly in $wpdb->query() argument — array built from sanitize_text_field output
function tp_implode_direct_in_query() {
    global $wpdb;
    $rows  = $wpdb->get_results( "SELECT slug FROM {$wpdb->terms}" );
    $slugs = [];
    foreach ( $rows as $row ) {
        // sanitize_text_field does not escape SQL quotes — slug can contain single quotes
        $slugs[] = "'" . sanitize_text_field( $row->slug ) . "'";
    }
    // ruleid: claude.php.wordpress.sqli.sanitize-text-field-array-implode-sql-injection
    $wpdb->query( "DELETE FROM {$wpdb->terms} WHERE slug IN (" . implode( ',', $slugs ) . ")" );
}

// TP: INSERT...SELECT UNION assembled via implode() directly in query arg
function tp_insert_select_union_direct() {
    global $wpdb;
    $new_id  = 42;
    $selects = [ "SELECT $new_id, 'key1', 'val1'", "SELECT $new_id, 'key2', 'val2'" ];
    // ruleid: claude.php.wordpress.sqli.sanitize-text-field-array-implode-sql-injection
    $wpdb->query( "INSERT INTO {$wpdb->postmeta} (post_id, meta_key, meta_value) " . implode( " UNION ALL ", $selects ) );
}

// NOTE: array_map('intval', $ids) before implode is a common FP that the rule DOES flag.
// This is safe (integers only), but pattern-not exclusion for this pattern does not work
// reliably with Semgrep deep expression matching. Triage manually when array elements
// come from intval/absint transforms. Documented in rule metadata.

// OK: $wpdb->prepare() wraps the implode result
function ok_prepare_with_implode() {
    global $wpdb;
    $placeholders = [ '%d', '%d' ];
    // ok: claude.php.wordpress.sqli.sanitize-text-field-array-implode-sql-injection
    $wpdb->query( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID IN (" . implode( ',', $placeholders ) . ")", 1, 2 ) );
}

// OK: each array element individually escaped via $wpdb->prepare() at its own push site
// (a bulk multi-row INSERT built one prepare()-escaped tuple per loop iteration, then
// implode()d in a later statement) — confirmed safe in a live audit (each element is a
// fully-quoted/escaped fragment, not a raw sanitize_text_field() value).
function ok_prepare_per_element_push_then_implode() {
    global $wpdb;
    $rows = [ [ 'id' => 1, 'name' => "o'brien" ], [ 'id' => 2, 'name' => 'bar' ] ];
    $values = [];
    foreach ( $rows as $row ) {
        $values[] = $wpdb->prepare( '(%d,%s)', $row['id'], $row['name'] );
    }
    // ok: claude.php.wordpress.sqli.sanitize-text-field-array-implode-sql-injection
    $wpdb->query( $wpdb->prepare( 'INSERT INTO %i (id, name) VALUES ', $wpdb->prefix . 'foo' ) . implode( ',', $values ) );
}
