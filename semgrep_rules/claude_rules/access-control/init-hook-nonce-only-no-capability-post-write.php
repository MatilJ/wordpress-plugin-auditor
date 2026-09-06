<?php
// Tests for claude.php.wordpress.access-control.init-hook-nonce-only-no-capability-post-write
// NOTE: join mode requires `semgrep login` — --test and standalone --config scans of
// this file will fail locally. Verify via sub-rule isolation or with login.

// ── TRUE POSITIVES ─────────────────────────────────────────────────────────────

// Case 1: string callback — wp_verify_nonce check, wp_insert_post, no capability check.
// Models Finding 1: WP Ultimate Review wur_meta_box_content_save() on init hook.
add_action( 'init', 'handle_review_submission' );

// ruleid: claude.php.wordpress.access-control.init-hook-nonce-only-no-capability-post-write
function handle_review_submission() {
    if ( ! isset( $_POST['_wpnonce'] ) ) {
        return;
    }
    if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'review-submission-nonce' ) ) {
        return;
    }
    $postarr = [
        'post_title'   => sanitize_text_field( $_POST['title'] ),
        'post_content' => sanitize_textarea_field( $_POST['content'] ),
        'post_type'    => 'xs_review',
        'post_status'  => 'publish',
    ];
    wp_insert_post( $postarr );
}

// Case 2: string callback — if-conditional nonce check, wp_update_post, no capability check.
add_action( 'init', 'handle_entry_update' );

// ruleid: claude.php.wordpress.access-control.init-hook-nonce-only-no-capability-post-write
function handle_entry_update() {
    if ( isset( $_POST['entry_id'] ) && wp_verify_nonce( $_POST['_nonce'], 'update-entry' ) ) {
        wp_update_post( [ 'ID' => absint( $_POST['entry_id'] ), 'post_status' => 'publish' ] );
    }
}

// Case 3: check_ajax_referer variant — also nonce-only, no capability.
add_action( 'init', 'handle_delete_submission' );

// ruleid: claude.php.wordpress.access-control.init-hook-nonce-only-no-capability-post-write
function handle_delete_submission() {
    if ( ! isset( $_POST['delete_id'] ) ) {
        return;
    }
    check_ajax_referer( 'delete-submission', '_wpnonce' );
    wp_delete_post( absint( $_POST['delete_id'] ), true );
}

// ── FALSE POSITIVES (ok) ───────────────────────────────────────────────────────

// Case 4: nonce check PLUS capability check — properly gated.
add_action( 'init', 'gated_review_submission' );

// ok: claude.php.wordpress.access-control.init-hook-nonce-only-no-capability-post-write
function gated_review_submission() {
    if ( ! isset( $_POST['_wpnonce'] ) ) {
        return;
    }
    if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'review-submission-nonce' ) ) {
        return;
    }
    if ( ! current_user_can( 'publish_posts' ) ) {
        return;
    }
    wp_insert_post( [ 'post_type' => 'xs_review', 'post_status' => 'publish' ] );
}

// Case 5: nonce check plus manage_options capability gate — admin-only, PR:H.
add_action( 'init', 'admin_only_post_create' );

// ok: claude.php.wordpress.access-control.init-hook-nonce-only-no-capability-post-write
function admin_only_post_create() {
    if ( ! isset( $_POST['action'] ) || 'create_template' !== $_POST['action'] ) {
        return;
    }
    check_ajax_referer( 'create-template', '_wpnonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Unauthorized.' );
    }
    wp_insert_post( [ 'post_type' => 'my_template', 'post_status' => 'publish' ] );
}
