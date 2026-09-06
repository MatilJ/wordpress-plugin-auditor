<?php

class Acme_Export_Handler {

    public function ajax_export_invoice_to_report() {
        $options = get_option('acme_export');

        $export_dir_file = wp_upload_dir()['basedir'] . '/acme-export-invoices';
        $export_path = isset($_POST['export_path']) ? sanitize_text_field($_POST['export_path']) : '';

        if (!empty($export_path) && $export_path == 'on') {
            $export_path_files = isset($_POST['export_path_files']) ? sanitize_text_field($_POST['export_path_files']) : $options['export_path_files'];
            if (empty($export_path_files)) {
                $export_path_files = $export_dir_file;
            }

            $upload_dir = wp_upload_dir()['basedir'];
            if (!file_exists($upload_dir . '/' . $export_path_files)) {
                // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
                mkdir($upload_dir . '/' . $export_path_files);
            }
            $csv_dir_file = $upload_dir . '/' . $export_path_files . '/export.csv';

            // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
            $fh = @fopen($csv_dir_file, 'w');
            fputcsv($fh, array('a', 'b'));
            fclose($fh);
        }
    }

    public function ajax_save_attachment() {
        $target_dir = sanitize_text_field($_REQUEST['target_dir']);
        $base = wp_upload_dir()['basedir'];
        // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
        file_put_contents($base . '/' . $target_dir . '/data.json', '{}');
    }

    // Mirrors the real-world two-method split: the AJAX handler reads and
    // weakly sanitizes the value, then hands it to a sibling method whose
    // name reads as "build/write an export/report file" — the actual
    // mkdir()/fopen() call lives inside that callee, one function-call hop
    // away, which plain intraprocedural taint tracking cannot see through.
    public function ajax_export_report() {
        $export_path_files = isset($_POST['export_path_files']) ? sanitize_text_field($_POST['export_path_files']) : '';
        // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
        $this->export_invoice_files($export_path_files);
    }

    public function export_invoice_files($export_path_files) {
        $base = wp_upload_dir()['basedir'];
        if (!file_exists($base . '/' . $export_path_files)) {
            mkdir($base . '/' . $export_path_files);
        }
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function ajax_export_invoice_to_report_fixed() {
        // Fixed shape: the destination directory is hardcoded, no
        // user-influenced path segment is joined into it.
        $upload_dir = wp_upload_dir()['basedir'];
        $export_dir = $upload_dir . '/acme-export-invoices';
        if (!file_exists($export_dir)) {
            mkdir($export_dir, 0755, true);
        }
        $csv_dir_file = $export_dir . '/export.csv';
        $fh = @fopen($csv_dir_file, 'w');
        fputcsv($fh, array('a', 'b'));
        fclose($fh);
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function ajax_save_attachment_sanitized() {
        $target_dir_raw = sanitize_text_field($_REQUEST['target_dir']);
        $target_dir = sanitize_file_name($target_dir_raw);
        $base = wp_upload_dir()['basedir'];
        file_put_contents($base . '/' . $target_dir . '/data.json', '{}');
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function ajax_lookup_receipt_totals() {
        // The delegate method name reads as a getter/lookup, not a
        // file/export write operation, so the naming heuristic sink does
        // not match even though a weakly-sanitized value is passed in.
        $receipt_key = sanitize_text_field($_POST['receipt_key']);
        $this->get_receipt_totals($receipt_key);
    }

    private function get_receipt_totals($receipt_key) {
        return array('total' => 0);
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function ajax_write_report_from_db() {
        global $wpdb;
        // The write DESTINATION is a fixed literal path; only the file
        // CONTENT is derived from a DB read, so no tainted request value
        // reaches the path argument of the write call.
        $row = $wpdb->get_row("SELECT summary FROM {$wpdb->prefix}acme_reports WHERE id = 1");
        file_put_contents(WP_CONTENT_DIR . '/uploads/acme-reports/summary.txt', $row->summary);
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function ajax_export_settings_json() {
        // The delegate method name reads as a getter ("get_export_json"), not
        // a file-write operation -- the get_ prefix signals a pure accessor
        // even though "export" alone would otherwise satisfy both naming-
        // heuristic lookaheads on this single token.
        $record_id = filter_var($_GET['record_id'], FILTER_SANITIZE_NUMBER_INT);
        $json = $this->get_export_json($record_id);
        echo $json;
    }

    private function get_export_json($record_id) {
        return json_encode(array('id' => $record_id));
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function ajax_export_by_record_name() {
        global $wpdb;
        // The write path is built from a DB-row field selected BY the
        // (weakly-sanitized) request id, not from the id value itself -- the
        // row content is a different value than the request parameter, so no
        // tainted request value reaches the write-path argument.
        $record_id = filter_var($_GET['record_id'], FILTER_SANITIZE_NUMBER_INT);
        $row = $wpdb->get_row($wpdb->prepare("SELECT record_name FROM {$wpdb->prefix}acme_records WHERE id = %d", $record_id));
        $filename = 'export-' . strtolower($row->record_name) . '.json';
        $fh = fopen('/tmp/' . $filename, 'w');
        fwrite($fh, '{}');
        fclose($fh);
    }
}

// CVE-2025-30834 (bit-assist) shape: a bundled Request-wrapper class's
// all() convenience accessor stands in for $_POST/$_GET — the superglobal
// itself never appears in this file — weakly sanitized with
// sanitize_text_field() (which does not strip '../'), then handed to a
// sibling "store"-named method that builds an upload directory and moves
// an uploaded file into it.
class Widget_Response_Controller {

    public function store($request) {
        $formData = array_map('sanitize_text_field', $request->all());
        $channelId = $formData['widget_channel_id'] ?? null;
        // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
        $this->storeFiles($request->files(), $channelId);
    }

    public function storeFiles($files, $channelId) {
        $uploadDir = WP_CONTENT_DIR . '/uploads/widget-responses/' . $channelId;
        wp_mkdir_p($uploadDir);
        foreach ($files as $file) {
            move_uploaded_file($file['tmp_name'], $uploadDir . '/' . wp_generate_uuid4());
        }
    }

    public function ajax_store_direct($request) {
        $channelId = $request->all()['widget_channel_id'];
        $uploadDir = WP_CONTENT_DIR . '/uploads/widget-responses/' . $channelId;
        // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
        wp_mkdir_p($uploadDir);
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function store_fixed($request) {
        // Fixed shape (mirrors the real 1.5.5 patch): the identifier is
        // validated/cast to an integer before it is used to build any
        // path, so it can never contain '/' or '..'.
        $formData = array_map('sanitize_text_field', $request->all());
        $channelId = absint($formData['widget_channel_id'] ?? 0);
        $this->storeFiles($request->files(), $channelId);
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function ajax_move_to_fixed_destination($tmpName) {
        // move_uploaded_file() destination is a fixed literal filename with
        // no user-influenced path segment.
        move_uploaded_file($tmpName, WP_CONTENT_DIR . '/uploads/widget-responses/fixed.dat');
    }
}

// CVE-2025-2941 (Drag and Drop Multiple File Upload for WooCommerce
// <= 1.1.4) shape: a POST array of "already uploaded" filenames is
// weakly re-sanitized per element and concatenated onto the upload
// directory with no realpath()/containment check, then handed to
// rename() as the SOURCE path -- an unauthenticated arbitrary file move.
class Dnd_Upload_Handler {

    public function add_cart_data() {
        $dir = trailingslashit(wp_upload_dir()['basedir'] . '/dnd-uploads');
        $post_files = isset($_POST['wc-upload-file']) ? array_map('sanitize_text_field', $_POST['wc-upload-file']) : null;
        $files = array();

        if ($post_files) {
            foreach ($post_files as $file) {
                $tmp_file = $dir . wc_clean(wp_unslash($file));
                if (file_exists($tmp_file)) {
                    $new_name = wp_unique_filename($dir, wp_basename($file));
                    // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
                    if (rename($tmp_file, $dir . $new_name)) {
                        $files[] = wp_basename($new_name);
                    }
                }
            }
        }
        return $files;
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-write-call
    public function add_cart_data_fixed() {
        // Fixed shape (mirrors the real 1.1.5 patch): realpath() resolves
        // the concatenated path and the result is checked for containment
        // against the base directory before it ever reaches rename().
        $dir = trailingslashit(wp_upload_dir()['basedir'] . '/dnd-uploads');
        $post_files = isset($_POST['wc-upload-file']) ? array_map('sanitize_text_field', $_POST['wc-upload-file']) : null;
        $files = array();

        if ($post_files) {
            foreach ($post_files as $file) {
                $file = wc_clean(wp_unslash($file));
                $tmp_file = realpath($dir . ltrim($file, '/'));
                if ($tmp_file !== false && strpos($tmp_file, realpath($dir)) === 0) {
                    $raw_name = sanitize_file_name(wp_basename($file));
                    $new_name = wp_unique_filename($dir, $raw_name);
                    if (file_exists($tmp_file)) {
                        if (rename($tmp_file, $dir . $new_name)) {
                            $files[] = wp_basename($new_name);
                        }
                    }
                }
            }
        }
        return $files;
    }
}
