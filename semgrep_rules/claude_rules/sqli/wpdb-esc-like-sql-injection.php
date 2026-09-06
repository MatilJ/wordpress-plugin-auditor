<?php
/**
 * Test cases for wpdb-esc-like-sql-injection.yaml
 *
 * Rule: wpdb-esc-like-reaches-wpdb-method (taint mode)
 * Source = $wpdb->esc_like(); Sanitizer = $wpdb->prepare(); Sink = $wpdb methods
 */

// ---------------------------------------------------------------------------
// TP: esc_like() flows into a wpdb execution method without prepare().
// ---------------------------------------------------------------------------
function r1_tp_direct_to_query($search) {
    global $wpdb;
    $like = $wpdb->esc_like($search);
    // ruleid: wpdb-esc-like-reaches-wpdb-method
    $wpdb->get_results("SELECT * FROM t WHERE col LIKE '%{$like}%'");
}

// TP: prepare() called with only the query string — the tainted value was already
// interpolated into it before the call, so there is no placeholder for prepare() to
// bind. A no-op prepare() call like this must NOT be treated as a sanitizer.
function r1_tp_noop_prepare_no_bind_args($search) {
    global $wpdb;
    $like = $wpdb->esc_like($search);
    // ruleid: wpdb-esc-like-reaches-wpdb-method
    $wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE col LIKE '%{$like}%'"));
}

// TP: same no-op prepare() shape, built via string concatenation across two lines.
function r1_tp_noop_prepare_concat_query($search) {
    global $wpdb;
    $like = $wpdb->esc_like($search);
    // ruleid: wpdb-esc-like-reaches-wpdb-method
    $wpdb->get_results($wpdb->prepare("SELECT * FROM t " . ( ! empty( $like ) ? "WHERE title LIKE '%{$like}%'" : '' )));
}

// OK: prepare() sanitizes the taint before it reaches the wpdb method.
function r1_ok_via_prepare($search) {
    global $wpdb;
    $like = '%' . $wpdb->esc_like($search) . '%';
    // ok: wpdb-esc-like-reaches-wpdb-method
    $wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE col LIKE %s", $like));
}

// OK: esc_like() concatenation passed into prepare() as an argument.
function r1_ok_assign_then_prepare($search) {
    global $wpdb;
    $like = '%' . $wpdb->esc_like($search) . '%';
    // ok: wpdb-esc-like-reaches-wpdb-method
    return $wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE col LIKE %s", $like));
}
