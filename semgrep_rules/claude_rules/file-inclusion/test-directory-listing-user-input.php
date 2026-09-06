<?php
// Test file for directory-listing-user-input rule

function bad_scandir_get() {
    $dir = $_GET['dir'];
    // ruleid: claude.php.wordpress.file.directory-listing-user-input
    $files = scandir($dir);
    echo json_encode($files);
}

function bad_glob_post() {
    $path = $_POST['path'];
    // ruleid: claude.php.wordpress.file.directory-listing-user-input
    $matches = glob($path . '/*.php');
    print_r($matches);
}

function bad_opendir_request() {
    $dir = $_REQUEST['directory'];
    // ruleid: claude.php.wordpress.file.directory-listing-user-input
    $handle = opendir($dir);
}

function good_scandir_basename() {
    $dir = basename($_GET['dir']);
    // ok: claude.php.wordpress.file.directory-listing-user-input
    $files = scandir('/uploads/' . $dir);
}

function good_scandir_realpath() {
    $dir = realpath($_GET['dir']);
    // ok: claude.php.wordpress.file.directory-listing-user-input
    $files = scandir($dir);
}

function good_scandir_sanitize_key() {
    $dir = sanitize_key($_GET['dir']);
    // ok: claude.php.wordpress.file.directory-listing-user-input
    $files = scandir('/templates/' . $dir);
}

function good_hardcoded_path() {
    // ok: claude.php.wordpress.file.directory-listing-user-input
    $files = scandir(ABSPATH . '/wp-content/uploads/');
}
