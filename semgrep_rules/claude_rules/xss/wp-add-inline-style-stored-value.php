<?php

// Test cases for claude.php.wordpress.xss.wp-add-inline-style-stored-value

// ruleid: claude.php.wordpress.xss.wp-add-inline-style-stored-value
$color = get_option('brand_color');
wp_add_inline_style('theme-style', '.brand { color: ' . $color . '; }');

// ruleid: claude.php.wordpress.xss.wp-add-inline-style-stored-value
$bg = get_post_meta($post_id, 'background_css', true);
wp_add_inline_style('plugin-css', $bg);

// ruleid: claude.php.wordpress.xss.wp-add-inline-style-stored-value
$font_size = get_user_meta($user_id, 'font_size', true);
$css = '.content { font-size: ' . $font_size . 'px; }';
wp_add_inline_style('custom-handle', $css);

// ok: claude.php.wordpress.xss.wp-add-inline-style-stored-value
$color = get_option('brand_color');
$safe_color = sanitize_hex_color($color);
wp_add_inline_style('theme-style', '.brand { color: ' . $safe_color . '; }');

// ok: claude.php.wordpress.xss.wp-add-inline-style-stored-value
$css_prop = get_post_meta($post_id, 'custom_css', true);
$safe = safecss_filter_attr($css_prop);
wp_add_inline_style('plugin-css', '.el { ' . $safe . ' }');

// ok: claude.php.wordpress.xss.wp-add-inline-style-stored-value
$size = get_option('font_size');
$safe_size = intval($size);
wp_add_inline_style('theme-style', '.content { font-size: ' . $safe_size . 'px; }');

// ok: claude.php.wordpress.xss.wp-add-inline-style-stored-value
wp_add_inline_style('admin-bar', '@media print { #wpadminbar { display:none; } }');
