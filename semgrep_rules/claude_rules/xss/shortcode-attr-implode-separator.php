<?php
// Test cases for claude.php.wordpress.xss.shortcode-attr-implode-separator

// ── TRUE POSITIVES ──────────────────────────────────────────────────────────

function render_tags_vulnerable($atts) {
    $glue = $atts['tags_glue'];
    $items = ['alpha', 'beta', 'gamma'];
    // ruleid: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return implode($glue, $items);
}

function render_inline_vulnerable($atts) {
    $items = ['foo', 'bar'];
    // ruleid: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return implode($atts['separator'], $items);
}

function render_from_get_vulnerable() {
    $sep = $_GET['sep'];
    $items = ['a', 'b', 'c'];
    // ruleid: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return implode($sep, $items);
}

function render_join_alias_vulnerable($atts) {
    $sep = $atts['glue'];
    $items = ['x', 'y'];
    // ruleid: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return join($sep, $items);
}

// ── FALSE POSITIVES (safe — should NOT fire) ───────────────────────────────

function render_tags_safe_esc_html($atts) {
    $glue = esc_html($atts['tags_glue']);
    $items = ['alpha', 'beta'];
    // ok: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return implode($glue, $items);
}

function render_tags_safe_inline_esc($atts) {
    $items = ['foo', 'bar'];
    // ok: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return implode(esc_html($atts['separator']), $items);
}

function render_static_separator() {
    $items = ['a', 'b', 'c'];
    // ok: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return implode(', ', $items);
}

function render_sanitized_separator($atts) {
    $sep = sanitize_text_field($atts['glue']);
    $items = ['p', 'q'];
    // ok: claude.php.wordpress.xss.shortcode-attr-implode-separator
    return implode($sep, $items);
}
