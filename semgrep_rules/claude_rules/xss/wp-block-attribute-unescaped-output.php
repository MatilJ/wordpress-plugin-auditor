<?php
// claude.php.wordpress.xss.wp-block-attribute-unescaped-output test cases

// ── Suspicious patterns (should fire — require manual verification of output context) ──

// NOTE: These fire as leads, NOT confirmed vulns. Block attribute values containing
// HTML are kses-filtered for Contributors (event handlers stripped). Exploitability
// depends on OUTPUT CONTEXT: attribute breakout (high confidence) vs HTML body (low
// confidence, requires empirical verification that payloads survive kses).

// Block attribute value echoed directly without escaping (Blocksy about-me pattern)
// ruleid: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
echo blocksy_default_akg('about_name', $atts, 'John Doe');

// Block attribute fallback passed through do_shortcode without escaping (Blocksy dynamic-data pattern)
// ruleid: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
$value = do_shortcode(blocksy_akg('fallback', $attributes, ''));

// Block attribute echoed via do_shortcode (Blocksy about-me about_text pattern)
// ruleid: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
$about_text = do_shortcode(blocksy_default_akg('about_text', $atts, 'default text'));

// Direct array key access echoed
// ruleid: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
echo $attributes['before'];

// Direct array key access on $atts echoed
// ruleid: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
echo $atts['custom_html'];

// do_shortcode on direct array access
// ruleid: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
$content = do_shortcode($attributes['content']);

// ── Safe patterns (should NOT fire) ──────────────────────────────────────────

// Escaped with esc_html before echo
// ok: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
echo esc_html($attributes['title']);

// Escaped with esc_attr
// ok: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
echo esc_attr(blocksy_akg('class', $attributes, ''));

// Escaped with wp_kses_post after do_shortcode
// ok: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
echo wp_kses_post(do_shortcode($attributes['content']));

// Integer cast — no XSS possible
// ok: claude.php.wordpress.xss.wp-block-attribute-unescaped-output
echo intval($attributes['count']);
