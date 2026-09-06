<?php
// Test file for the file-scope router/dispatcher LFI rule.

// ruleid: claude.php.wordpress.lfi.file-scope-router-param-no-allowlist
$page_mode = sanitize_text_field($_REQUEST['mode']);
include_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . $page_mode . '.php');

// ruleid: claude.php.wordpress.lfi.file-scope-router-param-no-allowlist
$view = $_GET['view'];
require ROUTER_DIR . '/' . $view . '.php';

// ok: claude.php.wordpress.lfi.file-scope-router-param-no-allowlist
$safe_mode = sanitize_text_field($_REQUEST['mode']);
$allowed_modes = array('index', 'details', 'checkout');
if (!in_array($safe_mode, $allowed_modes)) {
    $safe_mode = 'index';
}
include_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . $safe_mode . '.php');

// ok: claude.php.wordpress.lfi.file-scope-router-param-no-allowlist
$safe_view = $_GET['view'];
if (in_array($safe_view, array('home', 'about'), true)) {
    require ROUTER_DIR . '/' . $safe_view . '.php';
}

// ok: claude.php.wordpress.lfi.file-scope-router-param-no-allowlist
$safe_name = basename($_GET['tpl']);
include TEMPLATE_DIR . '/' . $safe_name . '.php';

// ok: claude.php.wordpress.lfi.file-scope-router-param-no-allowlist
$safe_key = sanitize_key($_POST['section']);
include_once SECTIONS_DIR . $safe_key . '.php';

function wrapped_dispatch() {
    // ok: claude.php.wordpress.lfi.file-scope-router-param-no-allowlist
    // Function-scoped occurrences of this same shape are covered by the
    // dataflow-based sibling rule, not this file-scope-only rule.
    $inner_mode = sanitize_text_field($_REQUEST['mode']);
    include_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . $inner_mode . '.php');
}
