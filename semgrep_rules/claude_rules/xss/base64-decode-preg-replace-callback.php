<?php
/**
 * Test cases for base64-decode-preg-replace-callback.yaml
 * Rule id: claude.php.wordpress.xss.base64-decode-preg-replace-callback
 *
 * Confirmed TP: luckywp-table-of-contents 2.1.14, Shortcode.php L315
 *   preg_replace_callback matching '<!-- lwptocEncodedToc BASE64 -->' comments;
 *   decoded output returned without sanitization → Stored XSS (CVSS 8.8).
 */

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// ruleid: claude.php.wordpress.xss.base64-decode-preg-replace-callback
$content = preg_replace_callback('#<!-- lwptocEncodedToc (.*?) -->#imsu', function ($matches) {
    return base64_decode($matches[1]);
}, $content);

// ruleid: claude.php.wordpress.xss.base64-decode-preg-replace-callback
$html = preg_replace_callback('/\[encoded:([A-Za-z0-9+\/=]+)\]/', function ($m) {
    return base64_decode($m[1]);
}, $html);

// ── Safe patterns ──────────────────────────────────────────────────────────────
// Note: plugin-internal round-trip encoding (e.g., Dom::prepareHtmlOut() in
// luckywp-table-of-contents) also matches this pattern — verify that the content
// being decoded can actually be influenced by an attacker before reporting.

// ok: claude.php.wordpress.xss.base64-decode-preg-replace-callback
$safe1 = preg_replace_callback('#<!-- lwptocEncodedToc (.*?) -->#imsu', function ($matches) {
    $decoded = base64_decode($matches[1]);
    if (!preg_match('/^\[lwptoc[^\]]*\]$/', $decoded)) {
        return '';
    }
    return $decoded;
}, $safe1);

// ok: claude.php.wordpress.xss.base64-decode-preg-replace-callback
$safe2 = preg_replace_callback('/\[encoded:([A-Za-z0-9+\/=]+)\]/', function ($m) {
    return wp_kses(base64_decode($m[1]), wp_kses_allowed_html('post'));
}, $safe2);

// ok: claude.php.wordpress.xss.base64-decode-preg-replace-callback
$safe3 = preg_replace_callback('/{base64:([^}]+)}/', function ($matches) {
    return wp_kses_post(base64_decode($matches[1]));
}, $safe3);

// ok: claude.php.wordpress.xss.base64-decode-preg-replace-callback
$safe4 = preg_replace_callback('/encoded\|([A-Za-z0-9+\/=]+)\|/', function ($m) {
    return esc_html(base64_decode($m[1]));
}, $safe4);
