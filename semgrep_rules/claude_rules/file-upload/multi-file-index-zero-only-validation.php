<?php

function handle_multi_upload_direct() {
    $whitelist_ext = array('jpg', 'jpeg', 'png', 'pdf');
    // ruleid: claude.php.wordpress.file-upload.multi-file-index-zero-only-validation
    $up_fileext = strtolower(pathinfo($_FILES['files']['name'][0], PATHINFO_EXTENSION));
    if (!in_array($up_fileext, $whitelist_ext, true)) {
        die('File type not allowed');
    }
    $handler = new Generic_Bundled_Upload_Handler(array('upload_dir' => '/tmp/'));
    return $handler->response;
}

function proSol_fileUploadProcess() {
    $submit_data = $_FILES["files"] ?? null;
    if (!$submit_data) {
        die('No file uploaded');
    }
    // ruleid: claude.php.wordpress.file-upload.multi-file-index-zero-only-validation
    $org_filename = isset($submit_data['name'][0]) ? sanitize_file_name($submit_data['name'][0]) : '';
    // ruleid: claude.php.wordpress.file-upload.multi-file-index-zero-only-validation
    $tmp_fileloc = isset($submit_data['tmp_name'][0]) ? $submit_data['tmp_name'][0] : '';
    if (empty($org_filename) || empty($tmp_fileloc) || !is_uploaded_file($tmp_fileloc)) {
        die('Invalid file');
    }
    $up_fileext = strtolower(pathinfo($org_filename, PATHINFO_EXTENSION));
    if (!in_array($up_fileext, array('jpg', 'jpeg', 'png', 'pdf'), true)) {
        die('File type not allowed');
    }
    $handler = new Generic_Bundled_Upload_Handler(array('upload_dir' => '/tmp/'));
    return $handler->response;
}

function proSol_fileUploadProcess_fixed() {
    $submit_data = $_FILES["files"] ?? null;
    if (!$submit_data) {
        die('No file uploaded');
    }
    for ($file_idx = 0; $file_idx < count($submit_data['name']); $file_idx++) {
        // ok: claude.php.wordpress.file-upload.multi-file-index-zero-only-validation
        $org_filename = isset($submit_data['name'][$file_idx]) ? sanitize_file_name($submit_data['name'][$file_idx]) : '';
        $tmp_fileloc = isset($submit_data['tmp_name'][$file_idx]) ? $submit_data['tmp_name'][$file_idx] : '';
        if (empty($org_filename) || empty($tmp_fileloc) || !is_uploaded_file($tmp_fileloc)) {
            die('Invalid file');
        }
        $up_fileext = strtolower(pathinfo($org_filename, PATHINFO_EXTENSION));
        if (!in_array($up_fileext, array('jpg', 'jpeg', 'png', 'pdf'), true)) {
            die('File type not allowed');
        }
    }
    $handler = new Generic_Bundled_Upload_Handler(array('upload_dir' => '/tmp/'));
    return $handler->response;
}

function handle_single_file_upload() {
    global $wpdb;
    $name = get_post_meta(get_the_ID(), '_stored_name', true);
    // ok: claude.php.wordpress.file-upload.multi-file-index-zero-only-validation
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (!in_array($ext, array('jpg', 'png'), true)) {
        return false;
    }
    return $wpdb->get_var($wpdb->prepare("SELECT id FROM files WHERE name = %s", $name));
}
