<?php
// Test file for arbitrary-file-read rule — realpath sanitizer addition

function bad_file_read() {
    $path = $_GET['file'];
    // ruleid: claude.php.wordpress.file.arbitrary-file-read
    $data = file_get_contents($path);
    echo $data;
}

function good_file_read_realpath() {
    $path = realpath($_GET['file']);
    // ok: claude.php.wordpress.file.arbitrary-file-read
    $data = file_get_contents($path);
    echo $data;
}

function good_file_read_basename() {
    $name = basename($_GET['file']);
    // ok: claude.php.wordpress.file.arbitrary-file-read
    $data = file_get_contents('/safe/dir/' . $name);
    echo $data;
}

function good_file_read_sanitize_key() {
    $key = sanitize_key($_GET['file']);
    // ok: claude.php.wordpress.file.arbitrary-file-read
    $data = file_get_contents('/logs/' . $key);
    echo $data;
}

function bad_fopen_fpassthru() {
    $path = $_GET['file'];
    // ruleid: claude.php.wordpress.file.arbitrary-file-read
    $fp = fopen($path, 'rb');
    fpassthru($fp);
    fclose($fp);
}

function bad_fopen_fread_loop() {
    $path = $_POST['filepath'];
    // ruleid: claude.php.wordpress.file.arbitrary-file-read
    $fp = fopen($path, 'r');
    while (!feof($fp)) {
        echo fread($fp, 8192);
    }
    fclose($fp);
}

function good_fopen_basename() {
    $name = basename($_GET['file']);
    // ok: claude.php.wordpress.file.arbitrary-file-read
    $fp = fopen('/safe/dir/' . $name, 'rb');
    fpassthru($fp);
    fclose($fp);
}

function good_fopen_sanitize_file_name() {
    $name = sanitize_file_name($_POST['file']);
    // ok: claude.php.wordpress.file.arbitrary-file-read
    $fp = fopen(PLUGIN_DIR . '/exports/' . $name, 'rb');
    fpassthru($fp);
    fclose($fp);
}

function bad_filesize_weak_sanitizer() {
    $uploaded_file = sanitize_text_field($_POST['uploaded_file']);
    // ruleid: claude.php.wordpress.file.arbitrary-file-read
    $size = filesize($uploaded_file);
    echo $size;
}

function good_filesize_traversal_stripped() {
    $uploaded_file = sanitize_text_field($_POST['uploaded_file']);
    $uploaded_file = str_replace('..', '', $uploaded_file);
    // ok: claude.php.wordpress.file.arbitrary-file-read
    $size = filesize($uploaded_file);
    echo $size;
}

class Good_Delegated_Validation {
    function download() {
        $tmp_file_name = $_GET['file'];
        if ( ! $this->validate_file_path( $tmp_file_name ) ) {
            wp_die( 'Invalid file path.', 403 );
        }
        // ok: claude.php.wordpress.file.arbitrary-file-read
        readfile( $tmp_file_name );
    }

    private function validate_file_path( $file_path ) {
        $real_path = realpath( $file_path );
        if ( false === $real_path ) {
            return false;
        }
        $upload_base = realpath( wp_upload_dir()['basedir'] );
        return str_starts_with( $real_path, $upload_base . DIRECTORY_SEPARATOR );
    }
}

function bad_no_guard_at_all() {
    $tmp_file_name = $_GET['file'];
    // ruleid: claude.php.wordpress.file.arbitrary-file-read
    readfile( $tmp_file_name );
}
