<?php

function acme_delete_removed_field_files($upload, $stored_files, $field_name) {
    foreach ($stored_files as $k => $file) {
        if (!isset($_POST['files_' . $field_name][$k])) {
            // ruleid: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
            if (file_exists($upload['dir'] . $file)) {
                @unlink($upload['dir'] . $file);
            }
        }
    }
}

function acme_cleanup_attachment_record($attachment) {
    // ruleid: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
    if (file_exists($attachment->base_dir . $attachment->stored_name)) {
        unlink($attachment->base_dir . $attachment->stored_name);
    }
}

function acme_delete_removed_field_files_fixed($upload, $stored_files, $field_name) {
    foreach ($stored_files as $k => $file) {
        if (!isset($_POST['files_' . $field_name][$k])) {
            $real_file = realpath($upload['dir'] . $file);
            // ok: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
            if (file_exists($upload['dir'] . $file) && strpos($real_file, '/acme_uploads/') !== false) {
                @unlink($upload['dir'] . $file);
            }
        }
    }
}

function acme_delete_own_asset($post_id, $upload) {
    $rel_path = get_post_meta($post_id, 'asset_path', true);
    $valid = validate_file($rel_path);
    if ($valid !== 0) {
        return;
    }
    // ok: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
    if (file_exists($upload['dir'] . $rel_path)) {
        unlink($upload['dir'] . $rel_path);
    }
}

function acme_url_to_path($file_url) {
    static $upload_dir = null;
    if (!$upload_dir) {
        $upload_dir = wp_get_upload_dir();
    }
    return str_replace($upload_dir['baseurl'], $upload_dir['basedir'], $file_url);
}

function acme_delete_entry_files($entry_id) {
    $form_data = acme_get_entry_data($entry_id);
    foreach ($form_data as $field_name => $value) {
        foreach ((array) $value as $file_url) {
            if (empty($file_url)) {
                continue;
            }
            // ruleid: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
            $file_path = acme_url_to_path(urldecode($file_url));

            if (file_exists($file_path)) {
                unlink($file_path);
            }
        }
    }
}

function acme_delete_submitted_attachment($request) {
    // ruleid: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
    $path = urldecode($request['file_url']);
    if (is_file($path)) {
        unlink($path);
    }
}

function acme_delete_entry_files_fixed($entry_id, $subdir = 'acme-uploads/') {
    $form_data = acme_get_entry_data($entry_id);
    foreach ($form_data as $field_name => $value) {
        foreach ((array) $value as $file_url) {
            if (empty($file_url)) {
                continue;
            }
            $upload_dir = wp_upload_dir();
            $base_path = trailingslashit($upload_dir['basedir']) . trailingslashit($subdir);
            $filename = basename(urldecode($file_url));
            $file_path = $base_path . $filename;
            $real_file_path = realpath($file_path);
            $real_base_path = realpath($base_path);
            if (!$real_file_path || !$real_base_path || strpos($real_file_path, $real_base_path) !== 0) {
                continue;
            }
            // ok: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
            if (file_exists($real_file_path)) {
                unlink($real_file_path);
            }
        }
    }
}

function acme_delete_submitted_attachment_fixed($request) {
    $rel_path = rawurldecode($request['file_url']);
    $valid = validate_file($rel_path);
    if ($valid !== 0) {
        return;
    }
    $path = ACME_UPLOAD_DIR . $rel_path;
    // ok: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
    if (is_file($path)) {
        unlink($path);
    }
}

function acme_rest_delete_attachment($request) {
    // ruleid: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
    $file_path = ABSPATH . 'wp-content/uploads/' . base64_decode($request->get_param('file_token'));

    if (!file_exists($file_path)) {
        throw new Exception('File not found', 404);
    }

    wp_delete_file($file_path);
}

function acme_rest_delete_export($request) {
    // ruleid: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
    $path = UPLOAD_BASE . '/' . hex2bin($request->get_param('token'));
    if (!is_file($path)) {
        return;
    }
    unlink($path);
}

function acme_rest_delete_attachment_fixed($request) {
    $file_path = ABSPATH . 'wp-content/uploads/' . base64_decode($request->get_param('file_token'));

    $real_file_path = realpath($file_path);
    $real_base_path = realpath(ABSPATH . 'wp-content/uploads/acme') . DIRECTORY_SEPARATOR;

    if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) {
        throw new Exception('Invalid file path', 400);
    }

    if (!file_exists($file_path)) {
        throw new Exception('File not found', 404);
    }

    // ok: claude.php.wordpress.file-write-delete.file-exists-only-guard-before-delete
    wp_delete_file($file_path);
}
