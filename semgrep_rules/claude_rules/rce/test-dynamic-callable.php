<?php
// Test file for dynamic-callable-user-input rule — sanitizer additions

function bad_call_user_func() {
    $func = $_GET['func'];
    // ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
    call_user_func($func, 'arg');
}

function good_call_intval() {
    $func = intval($_GET['func']);
    // ok: claude.php.wordpress.rce.dynamic-callable-user-input
    call_user_func($func, 'arg');
}

function good_call_sanitize_key() {
    $func = sanitize_key($_GET['func']);
    // ok: claude.php.wordpress.rce.dynamic-callable-user-input
    call_user_func($func, 'arg');
}

function good_call_int_cast() {
    $func = (int) $_GET['func'];
    // ok: claude.php.wordpress.rce.dynamic-callable-user-input
    call_user_func($func, 'arg');
}
