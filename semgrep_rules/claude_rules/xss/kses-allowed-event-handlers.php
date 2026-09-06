<?php

// Test cases for claude.php.wordpress.xss.kses-allowed-event-handlers

$safe = wp_kses($input, array(
    'div' => array(
        'class' => true,
        // ruleid: claude.php.wordpress.xss.kses-allowed-event-handlers
        'onclick' => true,
    ),
));

$allowed = array(
    'img' => array(
        'src' => true,
        // ruleid: claude.php.wordpress.xss.kses-allowed-event-handlers
        'onerror' => true,
    ),
);
$filtered = wp_kses($data, $allowed);

$result = wp_kses($html, array(
    'body' => array(
        // ruleid: claude.php.wordpress.xss.kses-allowed-event-handlers
        'onload' => true,
    ),
));

// ok: claude.php.wordpress.xss.kses-allowed-event-handlers
$safe = wp_kses($input, array(
    'a' => array(
        'href' => true,
        'class' => true,
    ),
    'img' => array(
        'src' => true,
        'alt' => true,
    ),
));

// ok: claude.php.wordpress.xss.kses-allowed-event-handlers
$safe = wp_kses_post($input);

// ok: claude.php.wordpress.xss.kses-allowed-event-handlers
$safe = wp_kses($input, 'post');

// WP_Admin_Bar::add_node()'s 'meta' argument documented-ly supports an
// 'onclick' key — unrelated to a wp_kses() allowed-HTML array.
function add_command_palette_node($wp_admin_bar) {
    $wp_admin_bar->add_node(
        array(
            'id'    => 'command-palette',
            'title' => 'Command Palette',
            'href'  => '#',
            'meta'  => array(
                'class'   => 'hide-if-no-js',
                // ok: claude.php.wordpress.xss.kses-allowed-event-handlers
                'onclick' => 'wp.data.dispatch( "core/commands" ).open(); return false;',
            ),
        )
    );
}
