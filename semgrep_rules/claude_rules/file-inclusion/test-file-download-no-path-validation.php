<?php
// Test file for file-download-no-path-validation rule

// ruleid: claude.php.wordpress.file.download-endpoint-path-traversal
function bad_download_readfile() {
    $file = $_GET['file'];
    header('Content-Disposition: attachment; filename="download.dat"');
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

// ruleid: claude.php.wordpress.file.download-endpoint-path-traversal
function bad_download_file_get_contents() {
    $path = WP_CONTENT_DIR . '/' . $_POST['path'];
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="export.csv"');
    echo file_get_contents($path);
    exit;
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
function good_download_sanitize_file_name() {
    $name = sanitize_file_name($_GET['file']);
    $file = PLUGIN_DIR . '/exports/' . $name;
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Type: application/octet-stream');
    readfile($file);
    exit;
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
function good_download_basename() {
    $name = basename($_GET['file']);
    $file = WP_CONTENT_DIR . '/uploads/' . $name;
    header('Content-Disposition: attachment; filename="' . $name . '"');
    readfile($file);
    exit;
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
function good_download_realpath() {
    $file = $_GET['file'];
    $real = realpath($file);
    if (strpos($real, WP_CONTENT_DIR) !== 0) {
        wp_die('Access denied');
    }
    header('Content-Disposition: attachment; filename="' . basename($real) . '"');
    readfile($real);
    exit;
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
function good_download_validate_file() {
    $file = $_GET['file'];
    $valid = validate_file($file);
    if (0 !== $valid) {
        wp_die('Invalid file');
    }
    header('Content-Type: application/octet-stream');
    readfile(ABSPATH . $file);
    exit;
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
function good_download_sanitize_key() {
    $key = sanitize_key($_GET['log']);
    $file = WP_CONTENT_DIR . '/logs/' . $key . '.log';
    header('Content-Type: application/octet-stream');
    readfile($file);
    exit;
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
// Sanitization happens in a sibling helper method, not inline in the download
// handler itself — a common OOP delegation pattern (mirrors mailpoet 5.34.0
// ExportDownload::downloadFile() calling getDownloadFilePath()).
class GoodExportDownload {
    private function getDownloadFilePath($data) {
        $real = realpath(EXPORT_DIR . '/' . $data['token']);
        if (strpos($real, EXPORT_DIR) !== 0) {
            return false;
        }
        return $real;
    }

    public function downloadFile($data) {
        $filePath = $this->getDownloadFilePath($data);
        header('Content-Type: application/octet-stream');
        readfile($filePath);
        exit;
    }
}

// Same class shape as above, but no sanitizer method anywhere in the class —
// must still be flagged (proves the class-scope exclusion isn't over-broad).
class BadExportDownload {
    // ruleid: claude.php.wordpress.file.download-endpoint-path-traversal
    public function downloadFile($data) {
        $filePath = $data['token'];
        header('Content-Type: application/octet-stream');
        readfile($filePath);
        exit;
    }
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
// Path built from a hardcoded directory helper concatenated only with a class
// constant — no request-superglobal component, not attacker-influenceable.
class GoodExportReviewsDownload {
    const FILE_PATH = 'export_reviews.csv';

    public function handle_download() {
        $filename = get_temp_dir() . self::FILE_PATH;
        header('Content-Disposition: attachment; filename="export-reviews.csv"');
        header('Content-Type: text/csv');
        header('Content-Length: ' . filesize($filename));
        readfile($filename);
        exit;
    }
}

// ok: claude.php.wordpress.file.download-endpoint-path-traversal
// Path built from a hardcoded directory helper concatenated with a literal
// string — still fully hardcoded, not attacker-influenceable.
function good_download_hardcoded_literal() {
    $path = get_temp_dir() . 'plugin-export.csv';
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="plugin-export.csv"');
    readfile($path);
    exit;
}

// Same directory-helper-concat shape, but the second operand is request-derived,
// not a constant/literal — must still be flagged (proves the new exclusion
// isn't over-broad).
// ruleid: claude.php.wordpress.file.download-endpoint-path-traversal
function bad_download_dirfunc_concat_request_input() {
    $path = get_temp_dir() . $_GET['file'];
    header('Content-Type: application/octet-stream');
    readfile($path);
    exit;
}
