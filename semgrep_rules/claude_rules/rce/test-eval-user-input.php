<?php
// Test file for eval-user-input rule — sanitizer additions

function bad_eval() {
    $code = $_POST['code'];
    // ruleid: claude.php.wordpress.rce.eval-user-input
    eval($code);
}

function good_eval_intval() {
    $val = intval($_POST['val']);
    // ok: claude.php.wordpress.rce.eval-user-input
    eval('$x = ' . $val . ';');
}

function good_eval_int_cast() {
    $val = (int) $_POST['val'];
    // ok: claude.php.wordpress.rce.eval-user-input
    eval('$x = ' . $val . ';');
}

function good_eval_sanitize_key() {
    $key = sanitize_key($_POST['key']);
    // ok: claude.php.wordpress.rce.eval-user-input
    eval('$x = "' . $key . '";');
}
