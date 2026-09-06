<?php
// Test file for command-injection rule — sanitizer additions

function bad_command_injection() {
    $cmd = $_GET['cmd'];
    // ruleid: claude.php.wordpress.rce.command-injection
    system($cmd);
}

function good_escapeshellarg() {
    $arg = escapeshellarg($_GET['arg']);
    // ok: claude.php.wordpress.rce.command-injection
    system("ls " . $arg);
}

function good_intval_sanitizer() {
    $id = intval($_GET['id']);
    // ok: claude.php.wordpress.rce.command-injection
    exec("process --id=" . $id);
}

function good_absint_sanitizer() {
    $id = absint($_POST['id']);
    // ok: claude.php.wordpress.rce.command-injection
    exec("process --id=" . $id);
}

function good_int_cast_sanitizer() {
    $id = (int) $_GET['id'];
    // ok: claude.php.wordpress.rce.command-injection
    exec("process --id=" . $id);
}

function good_sanitize_key() {
    $key = sanitize_key($_GET['key']);
    // ok: claude.php.wordpress.rce.command-injection
    system("lookup " . $key);
}
