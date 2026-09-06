<?php

// Test cases for claude.php.wordpress.xss.ajax-echo-wp-die-html-xss

// TP: AJAX handler echoing raw data then wp_die
add_action('wp_ajax_nopriv_my_handler', 'my_ajax_handler');
// ruleid: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function my_ajax_handler() {
    $result = $_POST['data'];
    echo $result;
    wp_die();
}

// TP: AJAX handler echoing raw data then die
add_action('wp_ajax_another_handler', 'another_ajax_handler');
// ruleid: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function another_ajax_handler() {
    $html = '<div>' . $_POST['name'] . '</div>';
    echo $html;
    die();
}

// TP: AJAX handler echoing variable then exit
// ruleid: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function ajax_with_exit() {
    echo $_GET['callback'];
    exit;
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function safe_ajax_json() {
    $data = array('result' => $_POST['data']);
    wp_send_json_success($data);
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function safe_ajax_escaped() {
    echo esc_html($_POST['data']);
    wp_die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function safe_ajax_json_encode() {
    echo wp_json_encode(array('data' => $_POST['input']));
    wp_die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function safe_ajax_with_header() {
    header('Content-Type: application/json');
    echo json_encode(array('status' => 'ok'));
    wp_die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function safe_ajax_fixed_diagnostic_string() {
    if (!$ready) {
        echo "\nRETRY_ME: 1\n";
    }
    exit;
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function safe_ajax_literal_bookended_escaped_attrs() {
    if (!acf_verify_ajax()) {
        die();
    }
    $attrs = array('data-labels' => $_POST['labels']);
    echo '<div ' . acf_esc_attrs($attrs) . '></div>';
    die();
}

// TP: literal-bookended concatenation, but the middle segment is NOT
// wrapped in a recognized escaping function — must still be flagged.
// ruleid: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function unsafe_ajax_literal_bookended_no_escape() {
    echo '<div>' . $_POST['name'] . '</div>';
    die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
// Confirmed FP: kirki 6.1.1 libraries/framework/Supports/Url.php:72-77 —
// esc_url() already applied on the prior line; wp_json_encode() is the
// escaping mechanism for the <script> JS-string context, bookended by
// literal <script>/</script> content.
function safe_redirect_script_bookended_json_encode($redirect_url) {
    if (\headers_sent()) {
        $safe_url = esc_url($redirect_url);
        echo '<script>window.location.href = ' . wp_json_encode($safe_url) . ';</script>';
        exit;
    }
}

// TP: same literal-bookended json_encode() shape, but the encoded value
// is never passed through esc_url() (or any sanitizer) first — must still
// be flagged, since a bare json_encode() does not strip `"`/`<`/`>`.
// ruleid: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function unsafe_bookended_json_encode_no_prior_escape() {
    echo '<script>var x = ' . json_encode($_GET['callback']) . ';</script>';
    exit;
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
// sanitize_text_field() strips literal tag syntax before this plain-body
// echo — no innerHTML/attribute context exists downstream (wp_die() body).
function safe_ajax_sanitized_reflection() {
    check_admin_referer('my_data', 'my_check');
    echo sanitize_text_field($_POST['notice-check']);
    wp_die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function safe_ajax_sanitized_textarea() {
    echo sanitize_textarea_field($_POST['details']);
    wp_die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
// Literal-only translation call — developer-authored message text, no
// attacker input reaches the echoed value.
function safe_ajax_literal_translation() {
    if (!class_exists('DOMDocument')) {
        echo __('ERROR: class DOMDocument not found.', 'my-plugin');
        wp_die();
    }
}

// TP: translation call whose message argument is a VARIABLE, not a string
// literal — must still be flagged, since the printed text is not fixed.
// ruleid: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
function unsafe_ajax_variable_translation_arg() {
    echo __($_GET['msg'], 'my-plugin');
    wp_die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
// manage_options gate (brace-less if/return form): only an Administrator can
// trigger this request, so the reflected response is self-directed (PR:H).
function ajax_admin_only_layout_fetch() {
    if (!current_user_can('manage_options')) return false;
    check_ajax_referer('my_nonce', 'security');
    $remote = wp_remote_get('https://example.com/api');
    echo wp_remote_retrieve_body($remote);
    wp_die();
}

// ok: claude.php.wordpress.xss.ajax-echo-wp-die-html-xss
// error_get_last()'s message/file/line fields are PHP-engine-generated
// diagnostic text describing the interpreter's own fatal-error state, not
// attacker-supplied content. Confirmed FP: shortpixel-image-optimiser 6.5.5
// ErrorController::checkErrors() (shutdown-handler debug output).
function checkErrors() {
    $error = error_get_last();
    if (is_null($error)) {
        return;
    }
    echo '<PRE>' . $error['message'] . ' in ' . $error['file'] . ' on line ' . $error['line'] . '</PRE>';
    exit(' -Error Handler- ');
}
