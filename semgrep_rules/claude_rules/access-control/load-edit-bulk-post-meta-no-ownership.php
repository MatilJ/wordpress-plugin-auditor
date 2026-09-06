<?php
// Test cases for claude.php.wordpress.access-control.load-edit-bulk-post-meta-no-ownership
// Tests: bulk-posts nonce + foreach loop + no per-resource edit_post capability check.

// ── TRUE POSITIVE cases (ruleid) ──────────────────────────────────────────────────────────

// Handler verifies bulk-posts nonce, iterates post IDs in a foreach loop, writes post meta
// directly in the loop — no current_user_can('edit_post', $post_id) per-resource check.
function page_load_no_ownership_check() {
    $action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
    switch ( $action ) {
        case 'block':
        case 'unblock':
            // ruleid: claude.php.wordpress.access-control.load-edit-bulk-post-meta-no-ownership
            check_admin_referer( 'bulk-posts' );
            $posts = isset( $_REQUEST['post'] ) ? (array) $_REQUEST['post'] : array();
            foreach ( $posts as $post_id ) {
                $post_id = (int) $post_id;
                $status  = ( 'block' === $action ) ? 1 : 0;
                update_post_meta( $post_id, '_plugin_block', $status );
            }
            break;
    }
}

// Handler delegates per-ID work to a helper method (self::set_status) without
// a per-resource capability gate in the calling function body.
function page_load_delegate_no_ownership_check() {
    $action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
    if ( 'hide' === $action ) {
        // ruleid: claude.php.wordpress.access-control.load-edit-bulk-post-meta-no-ownership
        check_admin_referer( 'bulk-posts' );
        $post_ids = isset( $_REQUEST['post'] ) ? (array) $_REQUEST['post'] : array();
        foreach ( $post_ids as $pid ) {
            $pid = (int) $pid;
            self::set_block_status( 2, $pid, 'post' );
        }
    }
}

// ── FALSE POSITIVE cases (ok) ─────────────────────────────────────────────────────────────

// Per-resource edit_post check present inside the loop — each post is authorised.
function page_load_with_per_resource_check() {
    $action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
    if ( 'block' === $action ) {
        // ok: claude.php.wordpress.access-control.load-edit-bulk-post-meta-no-ownership
        check_admin_referer( 'bulk-posts' );
        $posts = isset( $_REQUEST['post'] ) ? (array) $_REQUEST['post'] : array();
        foreach ( $posts as $post_id ) {
            $post_id = (int) $post_id;
            if ( ! current_user_can( 'edit_post', $post_id ) ) {
                continue;
            }
            update_post_meta( $post_id, '_plugin_block', 1 );
        }
    }
}

// manage_options check before the loop — admin-only gate (PR:H, out of scope).
function page_load_manage_options_gate() {
    $action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
    if ( 'restrict_all' === $action ) {
        // ok: claude.php.wordpress.access-control.load-edit-bulk-post-meta-no-ownership
        check_admin_referer( 'bulk-posts' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized', 403 );
        }
        $posts = isset( $_REQUEST['post'] ) ? (array) $_REQUEST['post'] : array();
        foreach ( $posts as $post_id ) {
            $post_id = (int) $post_id;
            update_post_meta( $post_id, '_plugin_block', 1 );
        }
    }
}

// edit_others_posts check before the loop — elevates the required privilege.
function page_load_edit_others_gate() {
    $action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
    if ( 'hide' === $action ) {
        // ok: claude.php.wordpress.access-control.load-edit-bulk-post-meta-no-ownership
        check_admin_referer( 'bulk-posts' );
        if ( ! current_user_can( 'edit_others_posts' ) ) {
            return;
        }
        $posts = isset( $_REQUEST['post'] ) ? (array) $_REQUEST['post'] : array();
        foreach ( $posts as $post_id ) {
            $post_id = (int) $post_id;
            update_post_meta( $post_id, '_plugin_hidden', 1 );
        }
    }
}
