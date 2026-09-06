<?php
/**
 * Audit Helpers — must-use plugin for WP audit environment
 */

// Delete any existing lock when a post transitions to pending.
add_action( 'transition_post_status', function( $new_status, $old_status, $post ) {
    if ( $new_status === 'pending' ) {
        delete_post_meta( $post->ID, '_edit_lock' );
    }
}, 10, 3 );

// Block _edit_lock from being written to pending posts at the metadata layer.
// This stops wp_set_post_lock() regardless of what triggered it — heartbeat,
// autosave, REST API, or anything else.
function audit_helpers_block_pending_lock( $check, $post_id, $meta_key ) {
    if ( '_edit_lock' === $meta_key && 'pending' === get_post_status( $post_id ) ) {
        delete_post_meta( $post_id, '_edit_lock' );
        return false;
    }
    return $check;
}
add_filter( 'update_post_metadata', 'audit_helpers_block_pending_lock', 10, 3 );
add_filter( 'add_post_metadata',    'audit_helpers_block_pending_lock', 10, 3 );
