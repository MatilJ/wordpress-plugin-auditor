<?php
// Tests for claude.php.wordpress.access-control.get-status-publish-gate-bypass

function ajax_quickview_vulnerable() {
    $product = wc_get_product( absint( $_POST['product_id'] ) );
    // ruleid: claude.php.wordpress.access-control.get-status-publish-gate-bypass
    if ( ! current_user_can( 'read_product', $product->get_id() ) && ( $product->get_status() !== 'publish' ) ) {
        die( 'Permissions check failed!' );
    }
    echo $product->get_name();
}

function ajax_post_view_vulnerable() {
    $post = get_post( absint( $_GET['post_id'] ) );
    // ruleid: claude.php.wordpress.access-control.get-status-publish-gate-bypass
    if ( ! current_user_can( 'read', $post->ID ) && $post->get_status() !== 'publish' ) {
        wp_die( 'Access denied' );
    }
    echo $post->post_content;
}

// ok: claude.php.wordpress.access-control.get-status-publish-gate-bypass
function ajax_quickview_safe_or_logic() {
    $product = wc_get_product( absint( $_POST['product_id'] ) );
    if ( ! current_user_can( 'read_product', $product->get_id() ) || post_password_required( $product->get_id() ) ) {
        wp_die( 'Access denied' );
    }
    echo $product->get_name();
}

// ok: claude.php.wordpress.access-control.get-status-publish-gate-bypass
function ajax_product_view_capability_only() {
    $product = wc_get_product( absint( $_POST['product_id'] ) );
    if ( ! current_user_can( 'read_product', $product->get_id() ) ) {
        wp_die( 'Access denied' );
    }
    if ( post_password_required( $product->get_id() ) ) {
        wp_die( 'Password required' );
    }
    echo $product->get_name();
}

function nopriv_attachment_comments_vulnerable() {
    $attachment_id = absint( $_REQUEST['id'] );
    $parent_post   = get_post_parent( $attachment_id );
    if ( $parent_post instanceof WP_Post ) {
        // ruleid: claude.php.wordpress.access-control.get-status-publish-gate-bypass
        if (
            'publish' !== $parent_post->post_status
            && ! current_user_can( 'read_post', $parent_post->ID )
        ) {
            wp_send_json_error( 'Not authorized', 403 );
        }
    }
    echo wp_json_encode( get_comments( array( 'post_id' => $attachment_id ) ) );
}

function ajax_post_view_property_vulnerable() {
    $post = get_post( absint( $_GET['post_id'] ) );
    // ruleid: claude.php.wordpress.access-control.get-status-publish-gate-bypass
    if ( ! current_user_can( 'read', $post->ID ) && $post->post_status !== 'publish' ) {
        wp_die( 'Access denied' );
    }
    echo $post->post_content;
}

// ok: claude.php.wordpress.access-control.get-status-publish-gate-bypass
function nopriv_attachment_comments_safe() {
    $attachment_id = absint( $_REQUEST['id'] );
    $parent_post   = get_post_parent( $attachment_id );
    if ( $parent_post instanceof WP_Post ) {
        if (
            ! current_user_can( 'read_post', $parent_post->ID )
            || post_password_required( $parent_post->ID )
        ) {
            wp_send_json_error( 'Not authorized', 403 );
        }
    }
    echo wp_json_encode( get_comments( array( 'post_id' => $attachment_id ) ) );
}
