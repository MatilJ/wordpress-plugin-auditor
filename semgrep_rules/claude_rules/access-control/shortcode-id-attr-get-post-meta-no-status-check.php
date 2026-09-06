<?php
// Test cases for claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check

// === TRUE POSITIVES — should match ===

// Shortcode callback reads post meta directly from user-supplied ID with no status check.
// Contributor can read address/phone/email from draft stores via [my_address id=N].
function show_store_address( $atts ) {
    $atts = shortcode_atts( array( 'id' => '' ), $atts, 'my_address' );
    // ruleid: claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check
    $address = get_post_meta( $atts['id'], 'store_address', true );
    echo esc_html( $address );
}

// Multiple meta reads from user-supplied ID, no status gate anywhere in the function.
// Both get_post_meta() calls should fire — each reads private store data.
function show_store_hours( $atts ) {
    $atts = shortcode_atts( array( 'id' => '', 'template' => 'default' ), $atts, 'my_hours' );
    // ruleid: claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check
    $hours = get_post_meta( $atts['id'], 'store_hours', true );
    // ruleid: claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check
    $phone = get_post_meta( $atts['id'], 'store_phone', true );
    echo esc_html( $hours ) . ' ' . esc_html( $phone );
}

// shortcode_atts() wrapped in a helper function — still vulnerable, rule must fire.
// Pattern: $atts = wpsl_bool_check( shortcode_atts( apply_filters(...), $atts ) )
function show_store_coords( $atts ) {
    $atts = bool_helper( shortcode_atts( array( 'id' => '', 'zoom' => 14 ), $atts, 'my_coords' ) );
    // ruleid: claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check
    $lat = get_post_meta( $atts['id'], 'store_lat', true );
    echo esc_attr( $lat );
}

// === FALSE POSITIVES — should NOT match ===

// Safe: get_post_status() check before reading meta.
function show_store_address_safe( $atts ) {
    $atts = shortcode_atts( array( 'id' => '' ), $atts, 'my_address_safe' );
    $post_status = get_post_status( $atts['id'] );
    if ( 'publish' !== $post_status ) {
        return '';
    }
    // ok: claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check
    $address = get_post_meta( $atts['id'], 'store_address', true );
    echo esc_html( $address );
}

// Safe: current_user_can() check for per-post read access.
function show_store_private_hours( $atts ) {
    $atts = shortcode_atts( array( 'id' => '' ), $atts, 'my_private_hours' );
    if ( ! current_user_can( 'read_post', (int) $atts['id'] ) ) {
        return '';
    }
    // ok: claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check
    $hours = get_post_meta( $atts['id'], 'store_hours', true );
    echo esc_html( $hours );
}

// Safe: get_post() retrieval followed by status check.
function show_store_map_safe( $atts ) {
    $atts = shortcode_atts( array( 'id' => '' ), $atts, 'my_map_safe' );
    $post = get_post( (int) $atts['id'] );
    if ( ! $post || 'publish' !== $post->post_status ) {
        return '';
    }
    // ok: claude.php.wordpress.access-control.shortcode-id-attr-get-post-meta-no-status-check
    $lat = get_post_meta( $atts['id'], 'store_lat', true );
    $lng = get_post_meta( $atts['id'], 'store_lng', true );
    echo esc_attr( $lat ) . ',' . esc_attr( $lng );
}
