<?php
/**
 * Test cases for claude.php.wordpress.rce.do-shortcode-db-content
 *
 * Detects database-stored content flowing into do_shortcode()/apply_shortcodes()
 * without shortcode-stripping sanitization. Second-order ASE when the write
 * path is accessible to low-privilege users.
 * subcategory: audit — manual write-path triage required.
 */

// ─── Vulnerable patterns (audit leads) ───────────────────────────────────────

// TP: option value rendered via do_shortcode without sanitization.
function tp_option_to_do_shortcode() {
    $template = get_option('my_plugin_template');
    // ruleid: claude.php.wordpress.rce.do-shortcode-db-content
    echo do_shortcode( $template );
}

// TP: post meta rendered via do_shortcode.
function tp_post_meta_to_do_shortcode($post_id) {
    $content = get_post_meta($post_id, '_custom_content', true);
    // ruleid: claude.php.wordpress.rce.do-shortcode-db-content
    return do_shortcode( $content );
}

// TP: user meta rendered via do_shortcode.
function tp_user_meta_to_do_shortcode($user_id) {
    $bio = get_user_meta($user_id, 'custom_bio', true);
    // ruleid: claude.php.wordpress.rce.do-shortcode-db-content
    echo do_shortcode( $bio );
}

// TP: transient rendered via do_shortcode.
function tp_transient_to_do_shortcode() {
    $cached = get_transient('my_plugin_cache');
    // ruleid: claude.php.wordpress.rce.do-shortcode-db-content
    echo do_shortcode( $cached );
}

// TP: apply_shortcodes alias with option value.
function tp_option_to_apply_shortcodes() {
    $tpl = get_option('widget_template');
    // ruleid: claude.php.wordpress.rce.do-shortcode-db-content
    return apply_shortcodes( $tpl );
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// OK: strip_shortcodes applied before do_shortcode — shortcode syntax removed.
function ok_strip_shortcodes_before() {
    $content = get_option('my_plugin_template');
    $safe = strip_shortcodes( $content );
    // ok: claude.php.wordpress.rce.do-shortcode-db-content
    echo do_shortcode( $safe );
}

// OK: wp_strip_all_tags removes brackets and all HTML.
function ok_strip_all_tags_before() {
    $content = get_post_meta($post_id, '_content', true);
    $safe = wp_strip_all_tags( $content );
    // ok: claude.php.wordpress.rce.do-shortcode-db-content
    echo do_shortcode( $safe );
}

// OK: intval applied — result is integer, not shortcode string.
function ok_intval_before() {
    $val = get_option('my_plugin_count');
    $safe = intval( $val );
    // ok: claude.php.wordpress.rce.do-shortcode-db-content
    echo do_shortcode( '[counter value="' . $safe . '"]' );
}

// OK: hardcoded shortcode string, DB value only used as parameter after cast.
function ok_hardcoded_tag_with_db_id() {
    // ok: claude.php.wordpress.rce.do-shortcode-db-content
    echo do_shortcode( '[my_shortcode]' );
}
