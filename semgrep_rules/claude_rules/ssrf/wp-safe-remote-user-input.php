<?php
// claude.php.wordpress.ssrf.wp-safe-remote-user-input test cases
// Taint mode: source (REST/AJAX request param) → sink (wp_safe_remote_get/post)
// wp_safe_remote_get() calls wp_http_validate_url() internally, which blocks
// RFC-1918 (10.x, 172.16-31.x, 192.168.x) and loopback (127.x) but NOT 169.254.x.x.

// ─── Vulnerable patterns ──────────────────────────────────────────────────────

// REST endpoint: Contributor passes url param → wp_safe_remote_get — SSRF to IMDS.
// Mirrors greenshift init.php:3226+3258:
//   $url = sanitize_text_field( $request->get_param('url') );
//   $response = wp_safe_remote_get( $url );
$url1 = $request->get_param( 'url' );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response1 = wp_safe_remote_get( $url1 );

// sanitize_text_field strips HTML but does not validate IP ranges — still vulnerable.
$url2 = sanitize_text_field( $request->get_param( 'feed_url' ) );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response2 = wp_safe_remote_get( $url2 );

// $_POST directly to wp_safe_remote_post — vulnerable.
$url3 = $_POST['webhook_url'];
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response3 = wp_safe_remote_post( $url3 );

// wp_remote_get — no built-in reject_unsafe_urls; also vulnerable.
$url4 = $request->get_param( 'csv_url' );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response4 = wp_remote_get( $url4 );

// wp_safe_remote_head() — same wp_http_validate_url() gap.
$url_head1 = $_POST['url'];
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$resp_head1 = wp_safe_remote_head( $url_head1 );

// wp_remote_head() — no built-in reject_unsafe_urls; also vulnerable.
$url_head2 = $request->get_param( 'feed_url' );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$resp_head2 = wp_remote_head( $url_head2 );

// esc_url_raw() formats URL structure (scheme, encoding) but does NOT block IP ranges.
// 169.254.169.254 passes through esc_url_raw() unchanged — taint must propagate.
foreach ( $_POST['urls'] as $url ) {
    // ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
    $resp_foreach = wp_safe_remote_head( esc_url_raw( $url ), array( 'timeout' => 5 ) );
}

// esc_url() — same as esc_url_raw() for SSRF purposes; no IP-range blocking.
$url_esc = esc_url( $_POST['target'] );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$resp_esc = wp_safe_remote_get( $url_esc );

// sanitize_text_field + esc_url_raw chain — both are non-sanitizing for SSRF.
$raw_url_chain = sanitize_text_field( $_POST['feed'] );
$safe_url_chain = esc_url_raw( $raw_url_chain );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$resp_chain = wp_safe_remote_get( $safe_url_chain );

// sanitize_url() is a core alias of esc_url_raw() — same non-protection, no host/IP check.
$url8 = sanitize_url( $_GET['elementUrl'] );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response8 = wp_remote_get( $url8, array( 'sslverify' => false ) );

// Plugin-defined thin wrapper: forwards its own $url parameter straight into a
// remote-fetch call with no host validation of its own.
class Helper_Http {
    public static function http_get( $url, $args = array() ) {
        $response = wp_remote_get( $url, $args );
        return is_wp_error( $response ) ? false : wp_remote_retrieve_body( $response );
    }
}
$url9 = sanitize_url( $_GET['elementUrl'] );
// ruleid: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$data9 = Helper_Http::http_get( $url9, array( 'sslverify' => false ) );

// ─── Safe patterns ────────────────────────────────────────────────────────────

// wp_parse_url() decomposes the URL and the host is checked against an allowlisted
// value before any request is made — the taint chain breaks at wp_parse_url().
$raw_url10 = wp_unslash( $_GET['elementUrl'] );
$parts10   = wp_parse_url( $raw_url10 );
$allowed10 = wp_parse_url( home_url(), PHP_URL_HOST );
if ( isset( $parts10['host'] ) && strtolower( $parts10['host'] ) === strtolower( $allowed10 ) ) {
    $path10     = isset( $parts10['path'] ) ? $parts10['path'] : '/';
    $safe_url10 = 'https://' . $parts10['host'] . $path10;
    // ok: claude.php.wordpress.ssrf.wp-safe-remote-user-input
    $data10 = Helper_Http::http_get( $safe_url10, array( 'sslverify' => false ) );
}

// Developer-controlled URL — no user input.
// ok: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response5 = wp_safe_remote_get( 'https://api.example.com/v1/endpoint' );

// Integer parameter cannot be a valid URL.
$page_id = absint( $request->get_param( 'page_id' ) );
// ok: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response6 = wp_safe_remote_get( 'https://fixed.example.com/data/' . $page_id );

// sanitize_key output is [a-z0-9_-] — cannot form a URL scheme or host.
$category = sanitize_key( $request->get_param( 'category' ) );
// ok: claude.php.wordpress.ssrf.wp-safe-remote-user-input
$response7 = wp_safe_remote_get( 'https://api.example.com/v2/' . $category );
