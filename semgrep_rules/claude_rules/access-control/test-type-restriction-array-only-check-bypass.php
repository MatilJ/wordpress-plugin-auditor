<?php
// Test file for claude.php.wordpress.access-control.type-restriction-array-only-check-bypass

// --- TRUE POSITIVES ---

// TP1: mirrors the real pre-fix shape (Frontend Admin's ActionPost::load_data,
// pre-CVE-2025-14736 fix) — the containment check only runs when $form['post_type']
// is an array; a scalar restriction (e.g. a single-select post type, or the
// plugin's own internal type name) bypasses it entirely, and the id came
// straight from a url-query GET parameter.
function tp_post_type_restriction_scalar_bypass( $form ) {
    if ( isset( $_GET[ $form['url_query_post'] ] ) ) {
        $form['post_id'] = absint( $_GET[ $form['url_query_post'] ] );
    }

    $form_post = get_post( $form['post_id'] );
    if ( ! $form_post ) {
        $form['post_id'] = 'none';
        return $form;
    }

    $post_type = $form_post->post_type;

    // ruleid: claude.php.wordpress.access-control.type-restriction-array-only-check-bypass
    if ( is_array( $form['post_type'] ) && ! in_array( 'any', $form['post_type'] ) && ! in_array( $post_type, $form['post_type'] ) ) {
        $form['post_id'] = 'none';
    }

    return $form;
}

// TP2: simplified 2-clause generic variant — a different plugin's object
// resolver with the same is_array()-only gating bug and no companion check.
function tp_generic_object_type_restriction_bypass( $request ) {
    $target_id = isset( $_REQUEST['target_id'] ) ? absint( $_REQUEST['target_id'] ) : 0;
    $allowed_types = $request['allowed_types'];
    $actual_type = get_post_type( $target_id );

    // ruleid: claude.php.wordpress.access-control.type-restriction-array-only-check-bypass
    if ( is_array( $allowed_types ) && ! in_array( $actual_type, $allowed_types ) ) {
        $target_id = 0;
    }

    return get_post( $target_id );
}

// --- FALSE POSITIVES (fixed shapes) ---

// OK1: the real fix for CVE-2025-14736 — a standalone scalar-equality check,
// NOT gated behind is_array(), added alongside the array-only containment
// check to catch the scalar restriction case.
function ok_post_type_restriction_with_scalar_guard( $form ) {
    if ( isset( $_GET[ $form['url_query_post'] ] ) ) {
        $form['post_id'] = absint( $_GET[ $form['url_query_post'] ] );
    }

    $form_post = get_post( $form['post_id'] );
    if ( ! $form_post ) {
        $form['post_id'] = 'none';
        return $form;
    }

    $post_type = $form_post->post_type;

    // ok: claude.php.wordpress.access-control.type-restriction-array-only-check-bypass
    if ( is_array( $form['post_type'] ) && ! in_array( 'any', $form['post_type'] ) && ! in_array( $post_type, $form['post_type'] ) ) {
        $form['post_id'] = 'none';
    }

    if ( 'admin_form' == $form['post_type'] ) {
        $form['post_id'] = 'none';
        $form['hide_if_no_post'] = true;
    }

    return $form;
}

// OK2: the restriction is unconditionally normalized to an array before the
// containment test, so is_array() can never be false and a scalar
// restriction can no longer slip through unchecked.
function ok_object_type_restriction_array_cast( $request ) {
    $target_id = isset( $_REQUEST['target_id'] ) ? absint( $_REQUEST['target_id'] ) : 0;
    $allowed_types = $request['allowed_types'];
    $allowed_types = (array) $allowed_types;
    $actual_type = get_post_type( $target_id );

    // ok: claude.php.wordpress.access-control.type-restriction-array-only-check-bypass
    if ( is_array( $allowed_types ) && ! in_array( $actual_type, $allowed_types ) ) {
        $target_id = 0;
    }

    return get_post( $target_id );
}

// OK3: unrelated safe WP DB-read pattern — no restriction/containment gating
// of any kind, must not be flagged.
function ok_unrelated_wpdb_read( $slug ) {
    global $wpdb;
    // ok: claude.php.wordpress.access-control.type-restriction-array-only-check-bypass
    $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE post_name = %s", $slug ) );
    return $row;
}
