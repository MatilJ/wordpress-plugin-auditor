<?php

// ---- TRUE POSITIVES ----

function tp_handle_upload_inline_array() {
    $file = $_FILES['upload'];
    // ruleid: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, array('test_form' => false, 'test_type' => false));
}

function tp_handle_upload_short_array() {
    $file = $_FILES['upload'];
    // ruleid: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, ['test_form' => false, 'test_type' => false]);
}

function tp_handle_sideload_inline() {
    $file = array('name' => 'test.php', 'tmp_name' => '/tmp/xyz');
    // ruleid: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_sideload($file, array('test_type' => false));
}

function tp_handle_upload_variable_override() {
    $file = $_FILES['upload'];
    $overrides = array('test_form' => false);
    // ruleid: claude.php.wordpress.upload.wp-handle-upload-test-type-false-variable
    $overrides['test_type'] = false;
    $result = wp_handle_upload($file, $overrides);
}

function tp_handle_upload_variable_array_literal() {
    $file = $_FILES['upload'];
    // ruleid: claude.php.wordpress.upload.wp-handle-upload-test-type-false-variable
    $overrides = array('test_form' => false, 'test_type' => false);
    $result = wp_handle_upload($file, $overrides);
}

function tp_handle_sideload_variable() {
    $file = $_FILES['sideload'];
    // ruleid: claude.php.wordpress.upload.wp-handle-upload-test-type-false-variable
    $overrides = ['test_type' => false];
    $result = wp_handle_sideload($file, $overrides);
}

function tp_handle_upload_check_not_enforced() {
    $file = $_FILES['upload'];
    $filename = $file['name'];
    $validate = wp_check_filetype($filename);
    if ($validate['type'] !== 'text/plain') {
        // logged but request is not terminated - check has no effect
        error_log('bad type');
    }
    // ruleid: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, array('test_form' => false, 'test_type' => false));
}

// ---- FALSE POSITIVES ----

function ok_handle_upload_test_type_true() {
    $file = $_FILES['upload'];
    // ok: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, array('test_form' => false, 'test_type' => true));
}

function ok_handle_upload_no_test_type() {
    $file = $_FILES['upload'];
    // ok: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, array('test_form' => false));
}

function ok_handle_upload_test_form_false_only() {
    $file = $_FILES['upload'];
    // ok: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, array('test_form' => false));
}

function ok_handle_upload_default() {
    $file = $_FILES['upload'];
    // ok: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file);
}

function ok_handle_upload_check_filetype_enforced() {
    $file = $_FILES['upload'];
    $filename = $file['name'];
    $validate = wp_check_filetype($filename);
    if ($validate['type'] !== 'text/plain') {
        echo json_encode(['status' => 'error']);
        die();
    }
    // ok: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, array('test_form' => false, 'test_type' => false));
}

function ok_handle_upload_check_filetype_enforced_namespaced() {
    $file = $_FILES['upload'];
    $filename = $file['name'];
    $validate = \wp_check_filetype($filename);
    if ($validate['type'] !== 'text/plain') {
        echo json_encode(['status' => 'error']);
        die();
    }
    // ok: claude.php.wordpress.upload.wp-handle-upload-test-type-false
    $result = wp_handle_upload($file, array('test_form' => false, 'test_type' => false));
}
