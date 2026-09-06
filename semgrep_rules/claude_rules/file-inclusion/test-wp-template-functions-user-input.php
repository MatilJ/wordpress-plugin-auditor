<?php
// Test file for template-function-user-input rule

function bad_load_template_get() {
    $template = $_GET['template'];
    // ruleid: claude.php.wordpress.lfi.template-function-user-input
    load_template($template);
}

function bad_get_template_part_post() {
    $slug = $_POST['slug'];
    // ruleid: claude.php.wordpress.lfi.template-function-user-input
    get_template_part($slug);
}

function bad_locate_template_rest($request) {
    $name = $request->get_param('template');
    // ruleid: claude.php.wordpress.lfi.template-function-user-input
    locate_template(array($name), true);
}

function bad_load_template_request() {
    $tpl = $_REQUEST['tpl'];
    // ruleid: claude.php.wordpress.lfi.template-function-user-input
    load_template($tpl, true);
}

function bad_get_template_part_cookie() {
    $layout = $_COOKIE['layout'];
    // ruleid: claude.php.wordpress.lfi.template-function-user-input
    get_template_part($layout, 'main');
}

function good_template_sanitize_key() {
    $name = sanitize_key($_GET['style']);
    // ok: claude.php.wordpress.lfi.template-function-user-input
    get_template_part('content', $name);
}

function good_template_hardcoded() {
    // ok: claude.php.wordpress.lfi.template-function-user-input
    get_template_part('content', 'single');
}

function good_template_basename() {
    $name = basename($_GET['template']);
    // ok: claude.php.wordpress.lfi.template-function-user-input
    load_template('/templates/' . $name);
}

function good_template_sanitize_file_name() {
    $file = sanitize_file_name($_POST['template']);
    // ok: claude.php.wordpress.lfi.template-function-user-input
    locate_template(array($file));
}

function good_template_validate_file() {
    $tpl = validate_file($_GET['template']);
    // ok: claude.php.wordpress.lfi.template-function-user-input
    load_template($tpl);
}

function bad_template_no_allowlist_guard() {
    $template_id = $_REQUEST['tpl_id'];
    if (!$template_id) {
        return;
    }
    // ruleid: claude.php.wordpress.lfi.template-function-user-input
    locate_template(array($template_id));
}

function good_template_allowlist_guard_negated_if() {
    $template_id = $_REQUEST['tpl_id'];
    if (!$template_id) {
        return;
    }
    if (!is_valid_classic_template_id($template_id)) {
        return;
    }
    // ok: claude.php.wordpress.lfi.template-function-user-input
    locate_template(array($template_id));
}

function good_template_allowlist_guard_method() {
    $template_id = $_REQUEST['tpl_id'];
    if (!$this->is_allowed_template($template_id)) {
        return;
    }
    // ok: claude.php.wordpress.lfi.template-function-user-input
    $this->locate_template($template_id);
}
