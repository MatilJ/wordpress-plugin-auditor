<?php
/**
 * Test cases for claude.php.wordpress.xss.url-unicode-decode-no-esc-url
 *
 * VULNERABLE: html_entity_decode(stripslashes($url)) decodes stored \uXXXX sequences
 * to raw HTML chars; result flows to addcslashes($X, '/') which only escapes '/',
 * leaving '"', '<', '>' unmodified — HTML-unsafe in attribute context.
 *
 * SAFE: esc_url()/esc_attr()/esc_html() applied after decode and before addcslashes.
 */

// -------------------------------------------------------------------------
// VULNERABLE cases
// -------------------------------------------------------------------------

// Full CVE pattern: preg_replace converts \uXXXX → &#xXXXX; then html_entity_decode
// produces raw chars; addcslashes only escapes '/', leaving " and > raw.
function vuln_build_url( $url ) {
    $is_slashed = strpos( $url, '\/' ) !== false;
    $url = $is_slashed
        ? html_entity_decode( stripslashes( preg_replace( '/\\\u([\da-fA-F]{4})/', '&#x\1;', $url ) ) )
        : $url;
    $new_url = some_cdn_normalize( $url );
    // ruleid: claude.php.wordpress.xss.url-unicode-decode-no-esc-url
    return $is_slashed ? addcslashes( $new_url, '/' ) : $new_url;
}

// Simpler form: decode then addcslashes without sanitizing HTML chars
function vuln_decode_reslash( $url ) {
    $url = html_entity_decode( stripslashes( $url ) );
    // ruleid: claude.php.wordpress.xss.url-unicode-decode-no-esc-url
    return addcslashes( $url, '/' );
}

// -------------------------------------------------------------------------
// SAFE cases
// -------------------------------------------------------------------------

// Fix: esc_url() applied after decode — percent-encodes '"', '<', '>' before addcslashes
function safe_with_esc_url( $url ) {
    $is_slashed = strpos( $url, '\/' ) !== false;
    $url = $is_slashed
        ? html_entity_decode( stripslashes( preg_replace( '/\\\u([\da-fA-F]{4})/', '&#x\1;', $url ) ) )
        : $url;
    $url = esc_url( $url );
    $new_url = some_cdn_normalize( $url );
    // ok: claude.php.wordpress.xss.url-unicode-decode-no-esc-url
    return $is_slashed ? addcslashes( $new_url, '/' ) : $new_url;
}

// Safe: esc_attr() applied after decode before addcslashes
function safe_with_esc_attr( $url ) {
    $url = html_entity_decode( stripslashes( $url ) );
    $url = esc_attr( $url );
    // ok: claude.php.wordpress.xss.url-unicode-decode-no-esc-url
    return addcslashes( $url, '/' );
}
