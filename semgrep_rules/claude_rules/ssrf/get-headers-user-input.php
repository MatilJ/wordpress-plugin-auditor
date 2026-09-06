<?php

// Test cases for claude.php.wordpress.ssrf.get-headers-user-input

function vulnerable_ajax_get_headers() {
    $url = wp_unslash( $_POST['check_url'] );
    // ruleid: claude.php.wordpress.ssrf.get-headers-user-input
    $headers = get_headers( $url );
}

function vulnerable_rest_get_headers( $request ) {
    $url = $request->get_param( 'url' );
    // ruleid: claude.php.wordpress.ssrf.get-headers-user-input
    $headers = get_headers( $url, true );
}

function safe_hardcoded_get_headers() {
    // ok: claude.php.wordpress.ssrf.get-headers-user-input
    $headers = get_headers( 'https://api.example.com/status' );
}

function safe_validated_get_headers() {
    $url = wp_http_validate_url( $_GET['url'] );
    if ( ! $url ) {
        return;
    }
    // ok: claude.php.wordpress.ssrf.get-headers-user-input
    $headers = get_headers( $url );
}

function safe_key_get_headers() {
    $key = sanitize_key( $_GET['api'] );
    $url = 'https://api.example.com/' . $key . '/status';
    // ok: claude.php.wordpress.ssrf.get-headers-user-input
    $headers = get_headers( $url );
}
