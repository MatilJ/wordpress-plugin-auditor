<?php

// Debug/log file downloader: the routing decision (which log to serve) is
// made by a caller elsewhere (e.g. an init-hook handler reading $_GET), so
// this method never sees the request itself — but it also never checks who
// is asking before streaming the file to the browser.
class Plugin_Logger {
    public static function get_log_file_path() {
        return trailingslashit(WP_CONTENT_DIR) . 'plugin-debug.log';
    }

    // ruleid: claude.php.wordpress.access-control.file-download-handler-no-capability-check
    public function downloadLogFile() {
        $file = static::get_log_file_path();
        if ($file) {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($file) . '"');
            header('Content-Length: ' . filesize($file));
            readfile($file);
            exit;
        }
        http_response_code(404);
    }
}

// Unauthenticated export handler wired to a plain init hook; the caller does
// the $_GET check, this function does the serving with no auth of its own.
// ruleid: claude.php.wordpress.access-control.file-download-handler-no-capability-check
function myplugin_export_config_file() {
    $path = MYPLUGIN_DIR . '/exports/config-backup.json';
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="config-backup.json"');
    echo file_get_contents($path);
    exit;
}

// Same shape, but the method verifies the caller's capability before
// streaming the file — mirrors the official patch (added guard at top).
class Patched_Logger {
    public static function get_log_file_path() {
        return trailingslashit(WP_CONTENT_DIR) . 'plugin-debug.log';
    }

    // ok: claude.php.wordpress.access-control.file-download-handler-no-capability-check
    public function downloadLogFile() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $file = static::get_log_file_path();
        if ($file) {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($file) . '"');
            readfile($file);
            exit;
        }
        http_response_code(404);
    }
}

// A REST-registered export endpoint that checks the request nonce before
// serving the backup file.
// ok: claude.php.wordpress.access-control.file-download-handler-no-capability-check
function myplugin_rest_export_backup(WP_REST_Request $request) {
    check_ajax_referer('myplugin_export', 'nonce');
    $path = MYPLUGIN_DIR . '/backups/site-backup.zip';
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="site-backup.zip"');
    readfile($path);
    exit;
}
