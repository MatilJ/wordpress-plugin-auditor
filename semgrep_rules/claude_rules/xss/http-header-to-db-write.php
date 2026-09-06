<?php

// Test cases for claude.php.wordpress.xss.http-header-to-db-write

// --- TRUE POSITIVES ---

function log_visitor_referer_tp1() {
    $referer = $_SERVER['HTTP_REFERER'];
    // ruleid: claude.php.wordpress.xss.http-header-to-db-write
    update_option('last_referer', $referer);
}

function log_user_agent_tp2() {
    global $wpdb;
    $ua = $_SERVER['HTTP_USER_AGENT'];
    // ruleid: claude.php.wordpress.xss.http-header-to-db-write
    $wpdb->insert('wp_visitor_log', array('user_agent' => $ua));
}

function track_ip_tp3() {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    // ruleid: claude.php.wordpress.xss.http-header-to-db-write
    update_post_meta($post_id, '_visitor_ip', $ip);
}

function store_host_header_tp4() {
    global $wpdb;
    $host = $_SERVER['HTTP_HOST'];
    // ruleid: claude.php.wordpress.xss.http-header-to-db-write
    $wpdb->update('wp_analytics', array('host' => $host), array('id' => 1));
}

function log_accept_language_tp5() {
    $lang = $_SERVER["HTTP_ACCEPT_LANGUAGE"];
    // ruleid: claude.php.wordpress.xss.http-header-to-db-write
    update_user_meta($user_id, 'browser_lang', $lang);
}

// Extraction-helper shape: the real database write lives several call
// frames (often files) away and is out of reach of single-file taint
// analysis, so the unsanitized return value of the small getter is the
// reachable proxy. Mirrors the real pre-fix shape (trim() only, no
// sanitize_text_field()/wp_unslash()).
function get_user_agent_tp6() {
    $user_agent = (empty($_SERVER['HTTP_USER_AGENT']) ? '' : trim($_SERVER['HTTP_USER_AGENT']));
    // ruleid: claude.php.wordpress.xss.http-header-to-db-write
    return $user_agent;
}

function get_referer_tp7() {
    // ruleid: claude.php.wordpress.xss.http-header-to-db-write
    return $_SERVER['HTTP_REFERER'];
}

// --- FALSE POSITIVES (properly sanitized) ---

function log_referer_sanitized_fp1() {
    $referer = sanitize_text_field($_SERVER['HTTP_REFERER']);
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    update_option('last_referer', $referer);
}

function log_ua_sanitized_fp2() {
    global $wpdb;
    $ua = sanitize_text_field($_SERVER['HTTP_USER_AGENT']);
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    $wpdb->insert('wp_visitor_log', array('user_agent' => $ua));
}

function log_referer_esc_url_fp3() {
    $referer = esc_url_raw($_SERVER['HTTP_REFERER']);
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    update_option('last_referer', $referer);
}

function log_ip_intval_fp4() {
    $ip = (int) $_SERVER['HTTP_X_FORWARDED_FOR'];
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    update_post_meta($post_id, '_visitor_ip', $ip);
}

function log_ua_stripped_fp5() {
    $ua = wp_strip_all_tags($_SERVER['HTTP_USER_AGENT']);
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    update_user_meta($user_id, 'browser_ua', $ua);
}

// Extraction helper sanitizes at the point of extraction (the real fix
// shape) — every caller inherits a clean value regardless of how far away
// the eventual database write is.
function get_user_agent_fp6() {
    $user_agent = empty($_SERVER['HTTP_USER_AGENT'])
        ? ''
        : trim(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])));
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    return $user_agent;
}

// Plain WP DB-read pattern: the returned value originates from the
// database, not from a request header, so it must never be flagged
// regardless of the new return-sink branch.
function get_last_visitor_row_fp7() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}visitor_log ORDER BY id DESC LIMIT 1");
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    return $row;
}

// rawurlencode()-wrapped header value embedded as an outbound query-string
// parameter (license-check style API call). Confirmed FP: kirki 6.1.1
// includes/HelperFunctions.php:3227-3230 — the taint engine's default
// call-propagation treats http_get()'s return value ($info, then
// $info['data']) as tainted merely because HTTP_HOST appeared somewhere in
// its argument list; rawurlencode() breaks that chain at the source.
function get_my_license_info_fp8($license_key) {
    $host = rawurlencode($_SERVER['HTTP_HOST']);
    $info = json_decode(wp_remote_retrieve_body(wp_remote_get('https://example.com/?host=' . $host)), true);
    // ok: claude.php.wordpress.xss.http-header-to-db-write
    return $info['data'];
}
