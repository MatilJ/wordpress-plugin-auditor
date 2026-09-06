<?php
// Test cases for parse-url-fragment-unescaped-reassembly

// ---- VULNERABLE: fragment reassembled raw, single-quote '#' prefix ----

function replace_query_parameter( $key, $value, $url ) {
    $parts = wp_parse_url( $url );
    parse_str( $parts['query'], $query );
    $query[ $key ] = $value;
    if ( ! empty( $parts['fragment'] ) ) {
        // ruleid: claude.php.wordpress.xss.parse-url-fragment-unescaped-reassembly
        $parts['fragment'] = '#' . $parts['fragment'];
    } else {
        $parts['fragment'] = '';
    }
    $clean_query = urlencode_deep( $query );
    $clean_query = build_query( $clean_query );
    return $parts['scheme'] . '://' . $parts['host'] . $parts['path'] . '?' . $clean_query . $parts['fragment'];
}

// ---- VULNERABLE: fragment reassembled raw, double-quote '#' prefix, native parse_url() ----

function build_pagination_url( $base ) {
    $parts = parse_url( $base );
    if ( ! empty( $parts['fragment'] ) ) {
        // ruleid: claude.php.wordpress.xss.parse-url-fragment-unescaped-reassembly
        $parts['fragment'] = "#" . $parts['fragment'];
    }
    return $parts['scheme'] . '://' . $parts['host'] . $parts['path'] . $parts['fragment'];
}

// ---- SAFE: fragment rawurlencode()'d before the '#' prefix ----

function replace_query_parameter_safe( $key, $value, $url ) {
    $parts = wp_parse_url( $url );
    parse_str( $parts['query'], $query );
    $query[ $key ] = $value;
    if ( ! empty( $parts['fragment'] ) ) {
        // ok: claude.php.wordpress.xss.parse-url-fragment-unescaped-reassembly
        $parts['fragment'] = '#' . rawurlencode( $parts['fragment'] );
    } else {
        $parts['fragment'] = '';
    }
    $clean_query = urlencode_deep( $query );
    $clean_query = build_query( $clean_query );
    return $parts['scheme'] . '://' . $parts['host'] . $parts['path'] . '?' . $clean_query . $parts['fragment'];
}

// ---- SAFE: fragment esc_attr()'d before the '#' prefix ----

function build_pagination_url_safe( $base ) {
    $parts = parse_url( $base );
    if ( ! empty( $parts['fragment'] ) ) {
        // ok: claude.php.wordpress.xss.parse-url-fragment-unescaped-reassembly
        $parts['fragment'] = '#' . esc_attr( $parts['fragment'] );
    }
    return $parts['scheme'] . '://' . $parts['host'] . $parts['path'] . $parts['fragment'];
}
