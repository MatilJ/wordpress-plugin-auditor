<?php

// ---- TRUE POSITIVES ----

function tp_extract_post() {
    // ruleid: claude.php.wordpress.rce.extract-user-input
    extract($_POST);
    if ($is_admin) {
        delete_user($user_id);
    }
}

function tp_extract_get() {
    // ruleid: claude.php.wordpress.rce.extract-user-input
    extract($_GET);
}

function tp_extract_request() {
    // ruleid: claude.php.wordpress.rce.extract-user-input
    extract($_REQUEST);
}

function tp_extract_via_variable() {
    $data = $_POST;
    // ruleid: claude.php.wordpress.rce.extract-user-input
    extract($data);
}

function tp_extract_rest_params($request) {
    $params = $request->get_json_params();
    // ruleid: claude.php.wordpress.rce.extract-user-input
    extract($params);
}

class TestScopeWrapper extends ArrayObject {}

function tp_extract_scope_wrapper_getarraycopy() {
    $params = new TestScopeWrapper($_GET);
    // ruleid: claude.php.wordpress.rce.extract-user-input
    extract($params->getArrayCopy());
    include $template . '.php';
}

class TestViewHelper {
    protected static function get_view_path($name) {
        return '/views/' . $name . '.php';
    }

    public static function views($name, $data = []) {
        $file = self::get_view_path($name);
        // ruleid: claude.php.wordpress.rce.extract-user-input
        extract($data);
        if (is_readable($file)) {
            include $file;
        }
    }
}

function tp_extract_raw_data_param($name, $data = []) {
    $file = '/tpl/' . $name . '.php';
    // ruleid: claude.php.wordpress.rce.extract-user-input
    extract($data);
    include $file;
}

// ---- FALSE POSITIVES ----

function ok_extract_raw_data_param_extr_skip($name, $data = []) {
    $file = '/tpl/' . $name . '.php';
    // ok: claude.php.wordpress.rce.extract-user-input
    extract($data, EXTR_SKIP);
    include $file;
}

function ok_extract_with_extr_skip() {
    // ok: claude.php.wordpress.rce.extract-user-input
    extract($_POST, EXTR_SKIP);
}

function ok_extract_scope_wrapper_with_extr_skip() {
    $params = new TestScopeWrapper($_GET);
    // ok: claude.php.wordpress.rce.extract-user-input
    extract($params->getArrayCopy(), EXTR_SKIP);
}

function ok_shortcode_atts_extract($atts) {
    $atts = shortcode_atts(array(
        'id' => '',
        'class' => '',
        'title' => '',
    ), $atts);
    // ok: claude.php.wordpress.rce.extract-user-input
    extract($atts);
}

function ok_extract_hardcoded_array() {
    $defaults = array('width' => 100, 'height' => 200);
    // ok: claude.php.wordpress.rce.extract-user-input
    extract($defaults);
}

function ok_extract_int_cast() {
    $val = (int) $_POST['count'];
    // ok: claude.php.wordpress.rce.extract-user-input
    extract(array('count' => $val));
}
