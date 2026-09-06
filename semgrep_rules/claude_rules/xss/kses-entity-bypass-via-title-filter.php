<?php
// claude.php.wordpress.xss.kses-entity-bypass-via-title-filter test cases
//
// NOTE: Entity bypass (&#60;img&#62;) through these patterns is NOT exploitable.
// Per WHATWG HTML spec, character references in PCDATA are decoded to text
// characters, not markup. These rules flag missing esc_html() as a
// defense-in-depth / code quality issue only.

// Defense-in-depth issue: direct echo without esc_html (no wp_kses_post)
function test_direct_no_escape($post) {
    $title = apply_filters('the_title', $post->post_title, $post->ID);
    // ruleid: claude.php.wordpress.xss.kses-entity-bypass-via-title-filter
    echo $title;
}

// Safe: wp_kses_post is now a recognized sanitizer (entity bypass is not exploitable)
function test_walker_with_kses($object, $output, $indent) {
    $item_title = apply_filters('the_title', $object->post_title, $object->ID);
    $output .= $indent . '<li id="item_' . $object->ID . '"><span>' . $item_title . '</span>';
    // ok: claude.php.wordpress.xss.kses-entity-bypass-via-title-filter
    echo wp_kses_post($output);
}

// Safe: esc_html() applied to the filter output before concatenation
function test_escaped_ok($object, $output, $indent) {
    $item_title = esc_html(apply_filters('the_title', $object->post_title, $object->ID));
    $output .= $indent . '<li><span>' . $item_title . '</span>';
    // ok: claude.php.wordpress.xss.kses-entity-bypass-via-title-filter
    echo wp_kses_post($output);
}

// Safe: esc_attr() applied before reaching echo
function test_esc_attr_ok($post) {
    $title = esc_attr(apply_filters('the_title', $post->post_title, $post->ID));
    // ok: claude.php.wordpress.xss.kses-entity-bypass-via-title-filter
    echo wp_kses_post('<input value="' . $title . '">');
}

// Safe: htmlspecialchars() applied
function test_htmlspecialchars_ok($post) {
    $title = htmlspecialchars(apply_filters('the_title', $post->post_title, $post->ID));
    // ok: claude.php.wordpress.xss.kses-entity-bypass-via-title-filter
    echo wp_kses_post($title);
}

// Defense-in-depth: get_the_title() echoed directly without any escaping.
// Taint rule fires (get_the_title() source flows into echo sink).
function test_get_the_title_echo_no_escape() {
    // ruleid: claude.php.wordpress.xss.kses-entity-bypass-via-title-filter
    echo get_the_title();
}

// Safe: get_the_title() wrapped in esc_html()
function test_get_the_title_escaped_ok() {
    // ok: claude.php.wordpress.xss.kses-entity-bypass-via-title-filter
    echo esc_html(get_the_title());
}
