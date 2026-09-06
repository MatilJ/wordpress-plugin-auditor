<?php
// Test file for nopriv-comment-write-no-auth rule

// --- TRUE POSITIVES ---

// TP1: Nopriv AJAX hook + wp_insert_comment without auth
add_action( 'wp_ajax_nopriv_submit_review', 'handle_nopriv_review' );

// ruleid: claude.php.wordpress.access-control.nopriv-comment-write-no-auth
function handle_nopriv_review() {
    $comment_data = array(
        'comment_post_ID' => intval( $_POST['post_id'] ),
        'comment_content' => sanitize_text_field( $_POST['comment'] ),
        'comment_author'  => 'Guest',
    );
    wp_insert_comment( $comment_data );
    wp_die();
}

// TP2: admin_post_nopriv + wp_update_comment without auth
add_action( 'admin_post_nopriv_edit_comment', 'handle_nopriv_edit_comment' );

// ruleid: claude.php.wordpress.access-control.nopriv-comment-write-no-auth
function handle_nopriv_edit_comment() {
    $comment_id = intval( $_POST['comment_id'] );
    wp_update_comment( array(
        'comment_ID'      => $comment_id,
        'comment_content' => sanitize_text_field( $_POST['content'] ),
    ));
    wp_redirect( home_url() );
    exit;
}

// TP3: Nopriv hook, nonce check present but NO capability check — a public,
// unconditionally-localized nonce provides zero authorization value here
// (matches the real-world auto-approved-review-injection shape).
add_action( 'wp_ajax_nopriv_public_review', 'handle_public_review' );

// ruleid: claude.php.wordpress.access-control.nopriv-comment-write-no-auth
function handle_public_review() {
    check_ajax_referer( 'review_nonce', 'nonce' );
    wp_insert_comment( array(
        'comment_post_ID' => intval( $_POST['post_id'] ),
        'comment_content' => 'Reviewed',
    ));
    wp_die();
}

// --- TRUE NEGATIVES ---

// TN1: Nopriv hook but has capability check
add_action( 'wp_ajax_nopriv_auth_comment', 'handle_auth_comment' );

// ok: claude.php.wordpress.access-control.nopriv-comment-write-no-auth
function handle_auth_comment() {
    if ( ! current_user_can( 'edit_post', intval( $_POST['post_id'] ) ) ) {
        wp_die();
    }
    wp_insert_comment( array(
        'comment_post_ID' => intval( $_POST['post_id'] ),
        'comment_content' => 'Authorized',
    ));
    wp_die();
}

// TN2: Nopriv hook with a direct (non-if-wrapped) capability check.
add_action( 'wp_ajax_nopriv_logged_comment', 'handle_logged_comment' );

// ok: claude.php.wordpress.access-control.nopriv-comment-write-no-auth
function handle_logged_comment() {
    current_user_can( 'edit_post', intval( $_POST['post_id'] ) ) || wp_die();
    wp_insert_comment( array(
        'comment_post_ID' => intval( $_POST['post_id'] ),
        'comment_content' => 'Authorized',
    ));
    wp_die();
}
