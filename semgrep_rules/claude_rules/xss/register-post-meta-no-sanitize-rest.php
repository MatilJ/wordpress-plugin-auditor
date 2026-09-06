<?php
// Missing sanitize_callback — short array syntax
// ruleid: claude.php.wordpress.xss.register-post-meta-no-sanitize-rest
register_post_meta('post', 'my_custom_css', [
    'type'         => 'string',
    'single'       => true,
    'show_in_rest' => true,
]);

// Missing sanitize_callback — long array syntax
// ruleid: claude.php.wordpress.xss.register-post-meta-no-sanitize-rest
register_post_meta('my-cpt', 'layout_style', array(
    'type'         => 'string',
    'single'       => true,
    'show_in_rest' => true,
));

// ok: claude.php.wordpress.xss.register-post-meta-no-sanitize-rest
// sanitize_callback present — REST writes are sanitized before storage
register_post_meta('post', 'my_custom_css', [
    'type'              => 'string',
    'single'            => true,
    'show_in_rest'      => true,
    'sanitize_callback' => 'sanitize_text_field',
]);

// ok: claude.php.wordpress.xss.register-post-meta-no-sanitize-rest
// No show_in_rest — not exposed via REST API
register_post_meta('post', 'internal_flag', [
    'type'   => 'boolean',
    'single' => true,
]);

// ok: claude.php.wordpress.xss.register-post-meta-no-sanitize-rest
// _-prefixed key — WP Core defaults auth_callback to __return_false; non-admin REST writes blocked
register_post_meta('my-cpt', '_wptb_content_', [
    'type'         => 'string',
    'single'       => true,
    'show_in_rest' => true,
]);

// ok: claude.php.wordpress.xss.register-post-meta-no-sanitize-rest
// _-prefixed key (double-quote syntax)
register_post_meta('post', "_private_data", array(
    'type'         => 'string',
    'single'       => true,
    'show_in_rest' => true,
));
