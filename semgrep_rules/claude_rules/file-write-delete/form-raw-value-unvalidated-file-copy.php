<?php

function handle_form_submission_upload($field) {
    // ruleid: claude.php.wordpress.file-write-delete.form-raw-value-unvalidated-file-copy
    $val = $field['raw_value'];
    if (in_array($field['type'], array('upload', 'file'))) {
        $upload_files[$field['id']] = $val;
    }
    return $upload_files;
}

function handle_other_form_submission($data) {
    // ruleid: claude.php.wordpress.file-write-delete.form-raw-value-unvalidated-file-copy
    $v = $data['raw_value'];
    if ($data["type"] == "file") {
        $files[$data['name']] = $v;
    }
    return $files;
}

function handle_form_submission_patched($field, $raw_files) {
    $val = $field['raw_value'];
    // ok: claude.php.wordpress.file-write-delete.form-raw-value-unvalidated-file-copy
    if (in_array($field['type'], array('upload', 'file')) && isset($raw_files[$field['id']]) && isset($raw_files[$field['id']]['path'])) {
        $upload_files[$field['id']] = $raw_files[$field['id']]['path'];
    }
    return $upload_files;
}

function handle_form_submission_text_field($field) {
    $val = $field['raw_value'];
    // ok: claude.php.wordpress.file-write-delete.form-raw-value-unvalidated-file-copy
    if (in_array($field['type'], array('text', 'email'))) {
        $lead[$field['id']] = $val;
    }
    return $lead;
}

function load_stored_upload_path($id) {
    global $wpdb;
    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}form_entries WHERE id = %d", $id), ARRAY_A);
    // ok: claude.php.wordpress.file-write-delete.form-raw-value-unvalidated-file-copy
    $upload_files[$id] = $row['file_path'];
    return $upload_files;
}
