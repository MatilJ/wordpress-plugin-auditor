<?php
/**
 * Test cases for claude.php.wordpress.ssrf.mpdf-writehtml-user-input
 *
 * Rule tracks user-controlled input flowing (directly or via str_replace
 * propagation) into mPDF's WriteHTML() method without img/iframe tag removal.
 * mPDF fetches any <img src="..."> URL via cURL — SSRF, CWE-918.
 */

// ── MATCH: $_POST value substituted into HTML template via str_replace → WriteHTML ──

function test_post_via_str_replace_writehtml() {
    global $mpdf;
    $user_value = $_POST['custom_field'];
    $html = '<html><body><p>Hello {NAME}</p></body></html>';
    $html = str_replace( '{NAME}', $user_value, $html );
    // ruleid: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $html );
}

function test_request_direct_writehtml() {
    $mpdf = new \Mpdf\Mpdf();
    $user_html = $_REQUEST['template_html'];
    // ruleid: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $user_html );
}

function test_get_param_writehtml() {
    $mpdf = new \Mpdf\Mpdf();
    $request = new WP_REST_Request();
    $content = $request->get_param( 'content' );
    $template = '<div class="block">' . $content . '</div>';
    // ruleid: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $template );
}

function test_cookie_substitution_writehtml() {
    $mpdf = new \Mpdf\Mpdf();
    $sig = $_COOKIE['user_signature'];
    $html = str_replace( '{SIGNATURE}', $sig, '<p>{SIGNATURE}</p>' );
    // ruleid: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $html );
}

// ── NO MATCH: user input stripped of HTML tags before substitution ─────────────

function test_strip_tags_is_safe() {
    $mpdf = new \Mpdf\Mpdf();
    $user_value = $_POST['custom_field'];
    $safe = strip_tags( $user_value );
    $html = str_replace( '{NAME}', $safe, '<p>{NAME}</p>' );
    // ok: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $html );
}

function test_wp_kses_is_safe() {
    $mpdf = new \Mpdf\Mpdf();
    $content = $_POST['body'];
    $allowed = array( 'p' => array(), 'strong' => array() );
    $safe = wp_kses( $content, $allowed );
    // ok: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $safe );
}

function test_wp_kses_post_is_safe() {
    $mpdf = new \Mpdf\Mpdf();
    $body = $_POST['html_body'];
    $safe = wp_kses_post( $body );
    // ok: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $safe );
}

function test_intval_is_safe() {
    $mpdf = new \Mpdf\Mpdf();
    $id = intval( $_GET['id'] );
    $html = '<p>ID: ' . $id . '</p>';
    // ok: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $html );
}

function test_hardcoded_template_is_safe() {
    $mpdf = new \Mpdf\Mpdf();
    // No user input — HTML is fully developer-controlled.
    $html = '<html><body><h1>Invoice</h1><p>Thank you for your order.</p></body></html>';
    // ok: claude.php.wordpress.ssrf.mpdf-writehtml-user-input
    $mpdf->WriteHTML( $html );
}
