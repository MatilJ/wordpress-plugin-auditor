<?php

// Test cases for claude.php.wordpress.ssrf.fetch-feed-user-input

function vulnerable_ajax_feed_import() {
    $feed_url = wp_unslash( $_POST['feed_url'] );
    // ruleid: claude.php.wordpress.ssrf.fetch-feed-user-input
    $feed = fetch_feed( $feed_url );
}

function vulnerable_rest_feed_import( $request ) {
    $url = $request->get_param( 'url' );
    // ruleid: claude.php.wordpress.ssrf.fetch-feed-user-input
    $feed = fetch_feed( $url );
}

function safe_hardcoded_feed() {
    // ok: claude.php.wordpress.ssrf.fetch-feed-user-input
    $feed = fetch_feed( 'https://example.com/feed.rss' );
}

function safe_sanitize_key_feed() {
    $slug = sanitize_key( $_GET['category'] );
    $url = 'https://blog.example.com/category/' . $slug . '/feed/';
    // ok: claude.php.wordpress.ssrf.fetch-feed-user-input
    $feed = fetch_feed( $url );
}

function safe_validated_feed() {
    $url = wp_http_validate_url( $_POST['feed_url'] );
    if ( ! $url ) {
        return;
    }
    // ok: claude.php.wordpress.ssrf.fetch-feed-user-input
    $feed = fetch_feed( $url );
}
