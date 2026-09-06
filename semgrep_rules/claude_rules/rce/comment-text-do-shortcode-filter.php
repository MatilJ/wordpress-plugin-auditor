<?php
/**
 * Test cases for claude.php.wordpress.rce.comment-text-do-shortcode-filter
 *
 * Detects add_filter('comment_text', 'do_shortcode') which enables
 * arbitrary shortcode execution via public comments (unauthenticated).
 * CVE-2023-4549.
 */

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// TP: do_shortcode registered as comment_text filter — unauthenticated ASE.
// ruleid: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('comment_text', 'do_shortcode');

// TP: apply_shortcodes alias registered on comment_text.
// ruleid: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('comment_text', 'apply_shortcodes');

// TP: with priority argument.
// ruleid: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('comment_text', 'do_shortcode', 10);

// TP: get_comment_text filter variant.
// ruleid: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('get_comment_text', 'do_shortcode');

// TP: comment_excerpt filter variant.
// ruleid: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('comment_excerpt', 'do_shortcode');

// TP: double-quoted strings.
// ruleid: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter("comment_text", "do_shortcode");

// ─── Safe patterns ────────────────────────────────────────────────────────────

// OK: do_shortcode on the_content is standard WP Core behavior.
// ok: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('the_content', 'do_shortcode');

// OK: Custom function name, not do_shortcode/apply_shortcodes.
// ok: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('comment_text', 'my_custom_shortcode_handler');

// OK: widget_text filter with do_shortcode — different hook.
// ok: claude.php.wordpress.rce.comment-text-do-shortcode-filter
add_filter('widget_text', 'do_shortcode');
