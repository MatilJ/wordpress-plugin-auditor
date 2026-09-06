<?php
// Test file for file-download-stream-no-path-validation rule

// ruleid: claude.php.wordpress.file.download-stream-no-path-validation
function bad_stream_download_fpassthru() {
    $file = $_GET['file'];
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="download.dat"');
    $fp = fopen($file, 'rb');
    fpassthru($fp);
    fclose($fp);
}

// ruleid: claude.php.wordpress.file.download-stream-no-path-validation
function bad_stream_download_fread() {
    $path = ABSPATH . $_POST['path'];
    header('Content-Disposition: attachment; filename="export.csv"');
    header('Content-Type: application/octet-stream');
    $fp = fopen($path, 'r');
    while (!feof($fp)) {
        echo fread($fp, 8192);
    }
    fclose($fp);
}

// ok: claude.php.wordpress.file.download-stream-no-path-validation
function good_stream_download_basename() {
    $name = basename($_GET['file']);
    $path = PLUGIN_DIR . '/exports/' . $name;
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Type: application/octet-stream');
    $fp = fopen($path, 'rb');
    fpassthru($fp);
    fclose($fp);
}

// ok: claude.php.wordpress.file.download-stream-no-path-validation
function good_stream_download_sanitize_file_name() {
    $name = sanitize_file_name($_POST['filename']);
    $path = WP_CONTENT_DIR . '/uploads/' . $name;
    header('Content-Type: application/octet-stream');
    $fp = fopen($path, 'rb');
    fpassthru($fp);
    fclose($fp);
}

// ok: claude.php.wordpress.file.download-stream-no-path-validation
function good_stream_download_realpath() {
    $file = $_GET['file'];
    $real = realpath($file);
    header('Content-Disposition: attachment');
    $fp = fopen($real, 'rb');
    fpassthru($fp);
    fclose($fp);
}

// ok: claude.php.wordpress.file.download-stream-no-path-validation
function good_stream_download_sanitize_key() {
    $key = sanitize_key($_GET['log']);
    $path = WP_CONTENT_DIR . '/logs/' . $key . '.log';
    header('Content-Type: application/octet-stream');
    $fp = fopen($path, 'rb');
    fpassthru($fp);
    fclose($fp);
}
