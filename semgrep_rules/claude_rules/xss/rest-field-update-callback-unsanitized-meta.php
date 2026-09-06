<?php
// claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta test cases

// ── Vulnerable patterns (ruleid) ──────────────────────────────────────────────

// Exact brizy pattern: raw $meta_value passed directly to update_post_meta()
register_rest_field( 'post', 'example_focal_point', array(
    'get_callback' => function ( $post, $field_name, $request ) {
        return get_post_meta( $post['id'], $field_name, true );
    },
    // ruleid: claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta
    'update_callback' => function ( $meta_value, $post ) {
        update_post_meta( $post->ID, 'example_focal_point', $meta_value );
    },
) );

// Variant: add_post_meta sink, multiple post types
register_rest_field( array( 'post', 'page' ), 'my_custom_color', array(
    // ruleid: claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta
    'update_callback' => function ( $meta_value, $post ) {
        add_post_meta( $post->ID, 'my_custom_color', $meta_value );
    },
) );

// Variant: update_option sink
register_rest_field( 'post', 'site_wide_banner', array(
    // ruleid: claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta
    'update_callback' => function ( $meta_value, $post ) {
        update_option( 'my_plugin_banner', $meta_value );
    },
) );

// ── Safe patterns (ok) ────────────────────────────────────────────────────────

// Safe: sanitize_text_field() wraps $meta_value — third arg is not raw $meta_value
// ok: claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta
register_rest_field( 'post', 'safe_text_field', array(
    'update_callback' => function ( $meta_value, $post ) {
        update_post_meta( $post->ID, 'safe_text_field', sanitize_text_field( $meta_value ) );
    },
) );

// Safe: cast to int — (int) $meta_value is not the same AST node as $meta_value
// ok: claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta
register_rest_field( 'post', 'safe_count', array(
    'update_callback' => function ( $meta_value, $post ) {
        update_post_meta( $post->ID, 'safe_count', (int) $meta_value );
    },
) );

// Safe: intermediate $clean variable — write arg differs from closure param name
// ok: claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta
register_rest_field( 'post', 'safe_html', array(
    'update_callback' => function ( $meta_value, $post ) {
        $clean = wp_kses_post( $meta_value );
        update_post_meta( $post->ID, 'safe_html', $clean );
    },
) );

// Safe: update_post_meta called outside register_rest_field — pattern-inside filters this
// ok: claude.php.wordpress.xss.rest-field-update-callback-unsanitized-meta
function my_save_post_handler( $meta_value, $post_id ) {
    update_post_meta( $post_id, 'some_key', $meta_value );
}
