<?php
/**
 * Test cases for url-filter-obj-get-current-unescaped-echo.yaml
 * Rule id: claude.php.wordpress.xss.url-filter-obj-get-current-unescaped-echo
 */

global $berocket_parse_page_obj;

// TP: URL-filter state returned from get_current() echoed into JS string literal without esc_js().
// Mirrors the confirmed vulnerable pattern at js_composer.php:191 (WPBakery compatibility shim).
function tp_js_string_literal_no_escape() {
    global $berocket_parse_page_obj;
    $data = $berocket_parse_page_obj->get_current();
    // ruleid: claude.php.wordpress.xss.url-filter-obj-get-current-unescaped-echo
    echo $data['fullline'];
}

// TP: URL-filter state echoed directly into HTML output without any escaping.
function tp_html_output_no_escape() {
    global $berocket_parse_page_obj;
    $data = $berocket_parse_page_obj->get_current();
    $query = $data['query'];
    // ruleid: claude.php.wordpress.xss.url-filter-obj-get-current-unescaped-echo
    echo $query;
}

// OK: esc_js() applied — safe for JavaScript string literal context.
function ok_esc_js_applied() {
    global $berocket_parse_page_obj;
    $data = $berocket_parse_page_obj->get_current();
    // ok: claude.php.wordpress.xss.url-filter-obj-get-current-unescaped-echo
    echo esc_js( $data['fullline'] );
}

// OK: wp_json_encode() applied — safe JSON encoding for JS contexts.
function ok_wp_json_encode_applied() {
    global $berocket_parse_page_obj;
    $data = $berocket_parse_page_obj->get_current();
    // ok: claude.php.wordpress.xss.url-filter-obj-get-current-unescaped-echo
    echo wp_json_encode( $data['fullline'] );
}

// OK: esc_html() applied — safe for HTML body context.
function ok_esc_html_applied() {
    global $berocket_parse_page_obj;
    $data = $berocket_parse_page_obj->get_current();
    // ok: claude.php.wordpress.xss.url-filter-obj-get-current-unescaped-echo
    echo esc_html( $data['fullline'] );
}

// OK: esc_attr() applied — safe for HTML attribute context.
function ok_esc_attr_applied() {
    global $berocket_parse_page_obj;
    $data = $berocket_parse_page_obj->get_current();
    // ok: claude.php.wordpress.xss.url-filter-obj-get-current-unescaped-echo
    echo esc_attr( $data['filter'] );
}
