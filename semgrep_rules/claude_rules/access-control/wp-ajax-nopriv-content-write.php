<?php
// Test file for wp-ajax-nopriv-content-write rule

// --- TRUE POSITIVES ---

// TP1: Nopriv AJAX hook + wp_update_post without any auth
add_action( 'wp_ajax_nopriv_update_post', 'handle_nopriv_update' );

// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-content-write
function handle_nopriv_update() {
    $post_id = intval( $_POST['post_id'] );
    $title = sanitize_text_field( $_POST['title'] );
    wp_update_post( array( 'ID' => $post_id, 'post_title' => $title ) );
    wp_die();
}

// TP2: admin_post_nopriv hook + wp_insert_post without auth
add_action( 'admin_post_nopriv_submit_form', 'handle_nopriv_form_submit' );

// ruleid: claude.php.wordpress.access-control.wp-ajax-nopriv-content-write
function handle_nopriv_form_submit() {
    $args = array(
        'post_title'   => sanitize_text_field( $_POST['title'] ),
        'post_content' => wp_kses_post( $_POST['content'] ),
        'post_status'  => 'publish',
    );
    wp_insert_post( $args );
    wp_redirect( home_url() );
    exit;
}

// --- TRUE NEGATIVES ---

// TN1: Nopriv hook but has capability check
add_action( 'wp_ajax_nopriv_safe_update', 'handle_safe_nopriv_update' );

// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-content-write
function handle_safe_nopriv_update() {
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_die( 'Unauthorized' );
    }
    $post_id = intval( $_POST['post_id'] );
    wp_update_post( array( 'ID' => $post_id, 'post_title' => 'Safe' ) );
    wp_die();
}

// TN2: Nopriv hook but has nonce check
add_action( 'wp_ajax_nopriv_nonce_update', 'handle_nonce_nopriv_update' );

// ok: claude.php.wordpress.access-control.wp-ajax-nopriv-content-write
function handle_nonce_nopriv_update() {
    check_ajax_referer( 'my_nonce_action', 'security' );
    $post_id = intval( $_POST['post_id'] );
    wp_update_post( array( 'ID' => $post_id, 'post_title' => 'Nonce checked' ) );
    wp_die();
}

// TN3: Regular wp_ajax_ hook (not nopriv) — authenticated only
add_action( 'wp_ajax_auth_update', 'handle_auth_update' );

function handle_auth_update() {
    $post_id = intval( $_POST['post_id'] );
    wp_update_post( array( 'ID' => $post_id, 'post_title' => 'Auth only' ) );
    wp_die();
}
