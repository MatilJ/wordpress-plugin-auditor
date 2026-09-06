<?php

class Acme_File_Manager {
    private $dir;

    public function ajax_temp_file_delete() {
        check_ajax_referer('acme_form_nonce', '_wpnonce');
        $file_id = isset($_POST['acme_file_id']) ? sanitize_text_field(wp_unslash($_POST['acme_file_id'])) : '';
        if (!$file_id) {
            wp_send_json_error('No file ID provided');
        }
        // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
        if ($this->do_delete_temp_file($file_id)) {
            wp_send_json_success();
        } else {
            wp_send_json_error('Failed to delete file');
        }
    }

    public function do_delete_temp_file($file_id) {
        $file = "{$this->dir}/temp/$file_id";
        if (file_exists($file) && is_writable($file)) {
            @unlink($file);
            return true;
        }
        return false;
    }

    public function ajax_remove_upload() {
        $name = sanitize_text_field($_GET['name']);
        // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
        unlink($name);
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
    public function ajax_temp_file_delete_fixed() {
        check_ajax_referer('acme_form_nonce', '_wpnonce');
        $file_id = isset($_POST['acme_file_id']) ? sanitize_file_name(wp_unslash($_POST['acme_file_id'])) : '';
        if (!$file_id) {
            wp_send_json_error('No file ID provided');
        }
        if ($this->do_delete_temp_file($file_id)) {
            wp_send_json_success();
        } else {
            wp_send_json_error('Failed to delete file');
        }
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
    public function ajax_temp_file_delete_realpath_guarded() {
        check_ajax_referer('acme_form_nonce', '_wpnonce');
        $file_id = isset($_POST['acme_file_id']) ? sanitize_text_field(wp_unslash($_POST['acme_file_id'])) : '';
        $real = realpath("{$this->dir}/temp/{$file_id}");
        if (!$real || strpos($real, $this->dir) !== 0) {
            wp_send_json_error('Invalid file');
        }
        // Delete the realpath()-resolved (and prefix-checked) value itself,
        // not the raw $file_id — this is the safe idiom taint mode
        // recognizes: realpath() is a pattern-sanitizer, so $real is clean.
        if (@unlink($real)) {
            wp_send_json_success();
        }
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
    public function ajax_delete_transient_not_a_file() {
        $key = sanitize_text_field($_POST['key']);
        delete_transient($key);
    }

    public function ajax_remove_product_upload() {
        if (wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'checkout_file_upload')) {
            $name = sanitize_text_field($_POST['name']);
            $names = explode('/', $name);
            $path = $this->get_upload_dir();
            $path_main = $path . '/' . end($names);
            if (@is_readable($path_main) && @is_file($path_main)) {
                // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
                @unlink($path_main);
                wp_send_json(array('status' => 'ok'));
            }
        }
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
    public function ajax_remove_product_upload_realpath_guarded() {
        if (wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'checkout_file_upload')) {
            $name = sanitize_text_field(wp_unslash($_POST['name']));
            $names = explode('/', $name);
            $upload_dir = $this->get_upload_dir();
            $path_main = trailingslashit($upload_dir) . end($names);
            $real_upload_dir = realpath($upload_dir);
            $real_file_path = realpath($path_main);
            if ($real_upload_dir === false || $real_file_path === false || strpos($real_file_path, $real_upload_dir) !== 0) {
                wp_send_json(array('status' => 'error'));
            }
            if (is_file($real_file_path) && is_readable($real_file_path)) {
                unlink($real_file_path);
                wp_send_json(array('status' => 'ok'));
            }
        }
    }

    private function get_upload_dir() {
        return $this->dir . '/uploads/';
    }

    public function ajax_save_draft_folder() {
        check_ajax_referer('save-design', 'nonce');
        $draft_folder = wc_clean($_POST['draft_folder']);
        $path = $this->get_upload_dir() . '/' . $draft_folder;
        if (file_exists($path . '_old')) {
            // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
            Acme_IO::delete_folder($path . '_old');
        }
    }

    public function ajax_reupload_design_file($first_time) {
        $item_key = sanitize_text_field($_POST['item_key']);
        $path_dir = $this->get_upload_dir() . '/' . $item_key;
        if ($first_time == 1 && file_exists($path_dir . '_old')) {
            // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
            $this->remove_folder($path_dir . '_old');
        }
    }

    private function remove_folder($path) {
        // recursive delete helper (analogous to Nbdesigner_IO::delete_folder)
    }

    // Mirrors the real CVE-2026-9725 shape: the sanitizer call sits one
    // block deeper (a validate-or-fall-back-to-session-default idiom) than
    // the path-build + delete call, which are siblings in the parent block.
    public function ajax_upload_design_file($first_time) {
        if (isset($_POST['nbu_item_key']) && $_POST['nbu_item_key'] != '') {
            $nbu_item_key = sanitize_text_field($_POST['nbu_item_key']);
        } else {
            $nbu_item_key = substr(md5(uniqid()), 0, 5);
        }
        $path_dir = $this->get_upload_dir() . '/' . $nbu_item_key;
        if ($first_time == 1 && file_exists($path_dir . '_old')) {
            // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
            Acme_IO::delete_folder($path_dir . '_old');
        }
    }

    // $_POST['progressID'] is used only as the KEY argument of
    // get_transient() — the returned value is the server-computed upload
    // path stored earlier by a separate set_transient() call, never a
    // reflection of the key's own content.
    public function ajax_import_chunk_cleanup() {
        $progress_id = $_POST['progressID'];
        $file_name = get_transient($progress_id);
        if ($file_name) {
            // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
            $this->remove_file($file_name);
        }
    }

    public function remove_file($filename) {
        @unlink($filename);
    }

    // Negative control: the transient lookup result is safe, but $path is
    // later reassigned directly from raw request data before the delete
    // call — flow-sensitive tracking must still re-taint it.
    public function ajax_import_chunk_cleanup_tainted() {
        $progress_id = $_POST['progressID'];
        $path = get_transient($progress_id);
        if (isset($_GET['debug_path'])) {
            $path = $_GET['debug_path'];
        }
        // ruleid: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
        $this->remove_file($path);
    }

    // ok: claude.php.wordpress.file-write-delete.weak-sanitizer-request-param-to-delete-call
    public function ajax_save_draft_folder_fixed() {
        check_ajax_referer('save-design', 'nonce');
        $draft_folder_raw = wc_clean($_POST['draft_folder']);
        $draft_folder = basename($draft_folder_raw);
        $path = $this->get_upload_dir() . '/' . $draft_folder;
        if (file_exists($path . '_old')) {
            Acme_IO::delete_folder($path . '_old');
        }
    }
}
