<?php
/**
 * Test cases for claude.php.wordpress.access-control.wp-update-post-reparent-no-ownership-check
 *
 * Rule fires at the wp_update_post() call inside functions that:
 *  1. Call wp_update_post() with both 'ID' and 'post_parent' keys (a re-parenting operation)
 *  2. Do NOT call current_user_can() anywhere in the same function body
 */

// ── MATCH: wp_update_post re-parenting with no ownership check ────────────────

// TP1: array() syntax, ID first — mirrors the confirmed IDOR finding.
// The $attachment_id comes from order meta written from $_POST at checkout.
function update_attachment_ids_tp1( $order_id, $posted_data ) {
    $attachment_ids = explode( ',', get_post_meta( $order_id, '_additional_file', true ) );
    foreach ( $attachment_ids as $attachment_id ) {
        // ruleid: claude.php.wordpress.access-control.wp-update-post-reparent-no-ownership-check
        wp_update_post( array(
            'ID'          => $attachment_id,
            'post_parent' => $order_id,
        ) );
    }
}

// TP2: short array [] syntax — same pattern, different syntax variant.
function reparent_media_tp2( $order_id, $ids ) {
    foreach ( $ids as $id ) {
        // ruleid: claude.php.wordpress.access-control.wp-update-post-reparent-no-ownership-check
        wp_update_post( [
            'ID'          => $id,
            'post_parent' => $order_id,
        ] );
    }
}

// TP3: 'post_parent' key first — reversed key ordering.
function reparent_media_tp3( $parent_id, $child_id ) {
    // ruleid: claude.php.wordpress.access-control.wp-update-post-reparent-no-ownership-check
    wp_update_post( array(
        'post_parent' => $parent_id,
        'ID'          => $child_id,
    ) );
}

// TP4: short array with reversed key ordering.
function reparent_reversed_tp4( $parent_id, $child_id ) {
    // ruleid: claude.php.wordpress.access-control.wp-update-post-reparent-no-ownership-check
    wp_update_post( [
        'post_parent' => $parent_id,
        'ID'          => $child_id,
    ] );
}

// ── NO MATCH: ownership check present ─────────────────────────────────────────

// OK1: per-resource current_user_can('edit_post', $id) before the call.
function update_attachment_safe_ok1( $order_id, $attachment_id ) {
    if ( ! current_user_can( 'edit_post', $attachment_id ) ) {
        return;
    }
    // ok: claude.php.wordpress.access-control.wp-update-post-reparent-no-ownership-check
    wp_update_post( array(
        'ID'          => $attachment_id,
        'post_parent' => $order_id,
    ) );
}

// OK2: admin capability check via current_user_can('manage_options').
function admin_reparent_ok2( $post_id, $new_parent ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Unauthorized' );
    }
    // ok: claude.php.wordpress.access-control.wp-update-post-reparent-no-ownership-check
    wp_update_post( [
        'ID'          => $post_id,
        'post_parent' => $new_parent,
    ] );
}
