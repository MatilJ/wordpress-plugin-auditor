<?php
// claude.php.wordpress.xss.json-encode-return-html-string test cases
// Pattern rule: json_encode result embedded in PHP string via interpolation or
// concatenation inside a return statement — HTML output context.
//
// Annotation placement for Forms 1a/1b (assignment + interpolation):
//   Multi-statement patterns report the match at the first statement (json_encode
//   assignment). Place the test annotation on the line before that assignment.
// Annotation placement for Forms 2a/2b (inline concatenation in return):
//   Single-statement pattern; annotation goes on the line before the return.

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// Form 1a: json_encode assigned to var, return uses PHP string interpolation.
// Mirrors GiveWP BlockRenderController.php:23 — block render callback returns
// an HTML div with data-attributes='[json]' where single-quote injection is possible.
function vulnerable_block_render_interpolation( array $attributes ): string {
    // ruleid: claude.php.wordpress.xss.json-encode-return-html-string
    $encoded = json_encode( $attributes );
    $blockId  = uniqid( 'block-' );
    return "<div id='block-{$blockId}' data-attributes='{$encoded}'></div>";
}

// Form 1b: wp_json_encode assigned to var, then interpolated in return string.
function vulnerable_shortcode_wp_json_encode( array $atts ): string {
    // ruleid: claude.php.wordpress.xss.json-encode-return-html-string
    $settings = wp_json_encode( $atts );
    return "<div class='my-block' data-settings='{$settings}'></div>";
}

// Form 2a: json_encode called inline in string concatenation in return.
function vulnerable_concat_return( array $data ): string {
    // ruleid: claude.php.wordpress.xss.json-encode-return-html-string
    return '<div data-settings=\'' . json_encode( $data ) . '\'></div>';
}

// Form 2b: wp_json_encode called inline in string concatenation in return.
function vulnerable_wp_json_encode_concat( array $data ): string {
    // ruleid: claude.php.wordpress.xss.json-encode-return-html-string
    return '<div data-config="' . wp_json_encode( $data ) . '"></div>';
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// esc_attr() wraps the json_encode result inside the concatenated return string.
// deep match pattern-not: return <... esc_attr($ENCODED) ...> excludes this.
function safe_esc_attr_wraps_encoded( array $attributes ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $encoded = json_encode( $attributes );
    $blockId  = uniqid( 'block-' );
    return "<div id='block-{$blockId}' data-attributes='" . esc_attr( $encoded ) . "'></div>";
}

// esc_attr() wraps wp_json_encode result in concatenated return — safe.
function safe_esc_attr_wraps_wp_json_encode( array $atts ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $settings = wp_json_encode( $atts );
    return "<div data-settings='" . esc_attr( $settings ) . "'></div>";
}

// Bare return of json_encode result — function returns raw JSON, not HTML.
// pattern-not: return $ENCODED excludes exactly this form.
function safe_bare_return_json( array $data ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $encoded = json_encode( $data );
    return $encoded;
}

// Bare return of wp_json_encode — same; pure JSON, not HTML output.
function safe_bare_return_wp_json_encode( array $data ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $encoded = wp_json_encode( $data );
    return $encoded;
}

// json_encode output passed to md5() — cache key; md5() returns [0-9a-f]{32},
// which cannot contain HTML metacharacters regardless of input.
function safe_md5_cache_key_json_encode( array $params ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $cache_args = json_encode( $params );
    return 'plugin_cache_' . md5( $cache_args );
}

// wp_json_encode output passed to md5() — same cache key pattern.
function safe_md5_cache_key_wp_json_encode( array $params ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $cache_args = (string) wp_json_encode( $params );
    return 'plugin_data_' . md5( $cache_args );
}

// json_encode output passed to base64_encode() for a URL query parameter — transport
// encoding, not HTML embedding. Mirrors mailpoet 5.34.0 Router::encodeRequestData().
function safe_base64_encode_json_encode( array $data ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $jsonEncoded = json_encode( $data );
    return rtrim( base64_encode( $jsonEncoded ), '=' );
}

// wp_json_encode output passed to rawurlencode() for a URL query parameter.
function safe_rawurlencode_wp_json_encode( array $data ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $encoded = wp_json_encode( $data );
    return rawurlencode( $encoded );
}

// json_encode result is REASSIGNED through base64_encode()+rtrim() (transport
// encoding, not embedded raw) in a statement separate from the return — the
// return expression itself never mentions json_encode/base64_encode literally,
// it just reads back the already-reassigned, now-safe variable. Mirrors
// optimole-wp 4.2.10 Optml_Dam::build_iframe_url() (inc/dam.php:470).
function safe_reassigned_through_base64_before_return( array $data ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $data = json_encode( $data );
    $data = rtrim( base64_encode( $data ), '=' );
    return add_query_arg( array( 'data' => $data ), 'https://dashboard.example.com/embed' );
}

// wp_json_encode result reassigned through md5() in a separate statement before
// the return — same reassign-then-reread idiom, hashed cache key form.
function safe_reassigned_through_md5_before_return( array $params ): string {
    // ok: claude.php.wordpress.xss.json-encode-return-html-string
    $cache_key = wp_json_encode( $params );
    $cache_key = md5( $cache_key );
    return 'plugin_cache_' . $cache_key;
}
