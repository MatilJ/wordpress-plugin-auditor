<?php
// Test cases for claude.php.wordpress.xss.unescaped-date-function-output

// ── TRUE POSITIVES ──────────────────────────────────────────────────────────

function get_modified_date_vulnerable($format, $post) {
    // ruleid: claude.php.wordpress.xss.unescaped-date-function-output
    return " " . get_the_modified_time($format, $post);
}

function get_date_vulnerable($format, $post) {
    // ruleid: claude.php.wordpress.xss.unescaped-date-function-output
    return " " . get_the_time($format, $post);
}

function build_date_concat_vulnerable($format, $post) {
    $output = '';
    // ruleid: claude.php.wordpress.xss.unescaped-date-function-output
    $output .= get_the_modified_time($format, $post);
    return $output;
}

function assign_date_vulnerable($format, $post) {
    // ruleid: claude.php.wordpress.xss.unescaped-date-function-output
    $date = get_the_time($format, $post);
    return $date;
}

// ── FALSE POSITIVES (safe — should NOT fire) ───────────────────────────────

function get_modified_date_safe($format, $post) {
    // ok: claude.php.wordpress.xss.unescaped-date-function-output
    return " " . esc_html(get_the_modified_time($format, $post));
}

function get_date_safe($format, $post) {
    // ok: claude.php.wordpress.xss.unescaped-date-function-output
    return ' ' . esc_html(get_the_time($format, $post));
}

function get_modified_date_esc_attr($format, $post) {
    // ok: claude.php.wordpress.xss.unescaped-date-function-output
    return esc_attr(get_the_modified_time($format, $post));
}

function get_date_static_format($post) {
    // ok: claude.php.wordpress.xss.unescaped-date-function-output
    return get_the_modified_time('Y-m-d', $post);
}

function get_time_static_format($post) {
    // ok: claude.php.wordpress.xss.unescaped-date-function-output
    return get_the_time('g:i a', $post);
}
