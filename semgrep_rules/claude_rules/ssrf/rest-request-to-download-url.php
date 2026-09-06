<?php
// REST callback — JSON body URL flows into download_url()
function rest_import_handler(WP_REST_Request $request) {
    $params = $request->get_json_params();
    $url    = $params['url'];
    // ruleid: claude.php.wordpress.ssrf.rest-request-to-download-url
    $tmp = download_url($url);
    return new WP_REST_Response(['file' => $tmp]);
}

// REST callback — get_param() flows into download_url()
function rest_fetch_image(WP_REST_Request $request) {
    $image_url = $request->get_param('image_url');
    // ruleid: claude.php.wordpress.ssrf.rest-request-to-download-url
    $file = download_url($image_url, 30);
    return new WP_REST_Response(['path' => $file]);
}

// ok: claude.php.wordpress.ssrf.rest-request-to-download-url
// Hardcoded URL — no user input involved
function fetch_static_asset() {
    $tmp = download_url('https://cdn.example.com/package.zip');
    return $tmp;
}

// ok: claude.php.wordpress.ssrf.rest-request-to-download-url
// Integer parameter — cannot be a URL
function rest_download_by_id(WP_REST_Request $request) {
    $attachment_id = intval($request->get_param('id'));
    $url = get_attached_file($attachment_id);
    $tmp = download_url($url);
    return new WP_REST_Response(['path' => $tmp]);
}
