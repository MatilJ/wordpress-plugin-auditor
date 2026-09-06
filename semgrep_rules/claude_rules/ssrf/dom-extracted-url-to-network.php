<?php
// dom-extracted-url-to-network test cases
// Simulates a favicon/scraper/OGP plugin that fetches remote HTML and
// extracts URLs from element attributes, then makes network requests.

// ── Vulnerable patterns ────────────────────────────────────────────────────

// 1. Attribute → curl_init: favicon downloader pattern (independent-analytics 2.14.9)
$html = file_get_contents('https://attacker.com/');
$doc = new DOMDocument();
@$doc->loadHTML($html);
$links = $doc->getElementsByTagName('link');
foreach ($links as $link) {
    // ruleid: claude.php.wordpress.ssrf.dom-extracted-url-to-network
    $ch = curl_init($link->getAttribute('href'));
    curl_exec($ch);
}

// 2. Attribute → curl_setopt: two-step curl pattern
$doc2 = new DOMDocument();
@$doc2->loadHTML($remote_content);
$anchors = $doc2->getElementsByTagName('a');
$href = $anchors->item(0)->getAttribute('href');
$ch2 = curl_init();
// ruleid: claude.php.wordpress.ssrf.dom-extracted-url-to-network
curl_setopt($ch2, CURLOPT_URL, $href);
curl_exec($ch2);

// 3. Attribute → wp_remote_get: WP HTTP API pattern
$doc3 = new DOMDocument();
@$doc3->loadHTML($page_html);
$img = $doc3->getElementsByTagName('img')->item(0);
$src = $img->getAttribute('src');
// ruleid: claude.php.wordpress.ssrf.dom-extracted-url-to-network
$response = wp_remote_get($src, ['timeout' => 5]);

// 4. Attribute → file_get_contents: stream wrapper pattern
$doc4 = new DOMDocument();
@$doc4->loadHTML($scraped_html);
$meta = $doc4->getElementsByTagName('meta')->item(0);
$content_url = $meta->getAttribute('content');
// ruleid: claude.php.wordpress.ssrf.dom-extracted-url-to-network
$blob = file_get_contents($content_url);

// ── Safe patterns ──────────────────────────────────────────────────────────

// 5. Attribute validated with wp_http_validate_url before curl
$doc5 = new DOMDocument();
@$doc5->loadHTML($html);
$links5 = $doc5->getElementsByTagName('link');
$raw_href = $links5->item(0)->getAttribute('href');
$safe_href = wp_http_validate_url($raw_href);
// ok: claude.php.wordpress.ssrf.dom-extracted-url-to-network
$ch5 = curl_init($safe_href);

// 6. Attribute validated with wp_http_validate_url before wp_remote_get
$doc6 = new DOMDocument();
@$doc6->loadHTML($ogp_html);
$og_img = $doc6->getElementsByTagName('meta')->item(0)->getAttribute('content');
$validated = wp_http_validate_url($og_img);
// ok: claude.php.wordpress.ssrf.dom-extracted-url-to-network
$resp = wp_remote_get($validated);

// 7. Attribute used as plain text (not a network request) — no sink reached
$doc7 = new DOMDocument();
@$doc7->loadHTML($html);
$title = $doc7->getElementsByTagName('title')->item(0)->getAttribute('class');
// ok: claude.php.wordpress.ssrf.dom-extracted-url-to-network
echo esc_html($title);

// 8. Attribute URL-encoded before use as a path suffix (not as full URL)
$doc8 = new DOMDocument();
@$doc8->loadHTML($html);
$path = $doc8->getElementsByTagName('a')->item(0)->getAttribute('data-path');
$safe_path = rawurlencode($path);
// ok: claude.php.wordpress.ssrf.dom-extracted-url-to-network
$resp2 = wp_remote_get('https://api.example.com/v1/' . $safe_path);
