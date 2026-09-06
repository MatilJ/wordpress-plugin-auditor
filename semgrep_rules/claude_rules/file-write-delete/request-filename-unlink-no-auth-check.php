<?php

// Vendored upload-library shape: filename comes from $_REQUEST, is
// basename()'d (blocks traversal) then concatenated with a fixed upload
// dir, but the deleting method performs no authorization check at all —
// mirrors CVE-2026-22448 (pitchprint <= 11.1.2, UploadHandler::delete()).
class Legacy_Upload_Handler {
    protected $upload_dir = '/wp-content/uploads/legacy/';

    public function get_file_name_param() {
        return basename(stripslashes($_REQUEST['file']));
    }

    public function delete() {
        $file_name = $this->get_file_name_param();
        $file_path = $this->upload_dir . $file_name;
        // ruleid: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
        $success = is_file($file_path) && unlink($file_path);
        return $success;
    }
}

// Unauthenticated AJAX handler wired to wp_ajax_nopriv_*, no capability
// check anywhere in the callback body.
add_action('wp_ajax_nopriv_myplugin_remove_asset', 'myplugin_remove_asset');
function myplugin_remove_asset() {
    $name = sanitize_file_name($_POST['asset']);
    $path = MYPLUGIN_UPLOAD_DIR . $name;
    // ruleid: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
    wp_delete_file($path);
    wp_send_json_success();
}

// Same shape, but the deleting function verifies the caller's capability
// before touching the filesystem — the authorization gap is closed.
add_action('wp_ajax_myplugin_admin_remove_asset', 'myplugin_admin_remove_asset');
function myplugin_admin_remove_asset() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('forbidden', 403);
    }
    $name = sanitize_file_name($_POST['asset']);
    $path = MYPLUGIN_UPLOAD_DIR . $name;
    // ok: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
    unlink($path);
    wp_send_json_success();
}

// Filename comes from a stored WP post meta value, and the handler
// verifies the caller is a logged-in user before touching the filesystem.
function myplugin_prune_stale_temp_file($post_id) {
    if (!is_user_logged_in()) {
        return;
    }
    $name = get_post_meta($post_id, '_myplugin_temp_file', true);
    $path = MYPLUGIN_TEMP_DIR . $name;
    if (is_file($path)) {
        // ok: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
        unlink($path);
    }
}

// WP core delete-lifecycle hook callback: before_delete_post only fires after
// WP core's own current_user_can('delete_post', $id) check has passed, so the
// registered callback needs no capability check of its own.
class Record_Cleanup {
    public function register() {
        add_action('before_delete_post', array($this, 'delete_owned_files'), 10, 2);
    }

    public function delete_owned_files($post_id, $post = null) {
        $path = get_post_meta($post_id, '_owned_upload_path', true);
        if (is_file($path)) {
            // ok: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
            wp_delete_file($path);
        }
    }
}

// Same class shape, but registered on an unrelated AJAX hook rather than a
// delete-lifecycle hook — the exemption must NOT apply here.
class Ajax_Cleanup {
    public function register() {
        add_action('wp_ajax_myplugin_cleanup', array($this, 'delete_owned_files'));
    }

    public function delete_owned_files() {
        $path = MYPLUGIN_UPLOAD_DIR . sanitize_file_name($_REQUEST['name']);
        // ruleid: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
        wp_delete_file($path);
    }
}

// Nonce-only guard, no capability/login check anywhere: check_ajax_referer()
// proves the request came from a page this site rendered, not that the
// requester may delete this specific file. Also registered wp_ajax_nopriv_*,
// so any visitor — logged in or not — can obtain a valid nonce and reach
// this. Mirrors CVE-2026-57709 (membership-for-woocommerce <= 3.1.0).
add_action('wp_ajax_nopriv_myplugin_remove_receipt', 'myplugin_remove_receipt');
add_action('wp_ajax_myplugin_remove_receipt', 'myplugin_remove_receipt');
function myplugin_remove_receipt() {
    check_ajax_referer('myplugin_nonce', 'nonce');
    $file_path = sanitize_text_field(wp_unslash($_POST['path']));
    if (file_exists($file_path)) {
        // ruleid: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
        unlink($file_path);
    }
}

// Same nonce-only shape, but the path is resolved with realpath() and
// confined to the uploads directory before deleting — the missing-
// authorization gap this branch targets is closed.
function myplugin_remove_receipt_fixed() {
    check_ajax_referer('myplugin_nonce', 'nonce');
    $file_path = sanitize_text_field(wp_unslash($_POST['path']));
    $real_path = realpath($file_path);
    $upload_dir = wp_upload_dir();
    if ($real_path && 0 === strpos($real_path, $upload_dir['basedir'])) {
        // ok: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
        unlink($real_path);
    }
}

// download_url() (WP core) downloads to a NEW, randomly-named local temp
// file and returns that generated path — the caller cannot choose or
// predict which file this is, even though $file (the URL argument) is
// request-influenced. Cleaning up that self-generated temp file on a
// failed-sideload path is not an arbitrary-file-deletion primitive.
function myplugin_generate_featured_image( $file, $post_id, $desc ) {
    $file_array = array();
    $file_array['name'] = basename( $file );
    $file_array['tmp_name'] = download_url( $file );
    if ( is_wp_error( $file_array['tmp_name'] ) ) {
        return false;
    }
    $id = media_handle_sideload( $file_array, $post_id, $desc );
    if ( is_wp_error( $id ) ) {
        // ok: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
        @unlink( $file_array['tmp_name'] );
        return $id;
    }
    return set_post_thumbnail( $post_id, $id );
}

// glob() enumerates only files that already exist on disk and match a
// fixed, developer-written wildcard — an attacker cannot inject an
// arbitrary target path through it. Common activation/cleanup-routine idiom.
function cleanup_legacy_pdf_files( $upload_dir ) {
    $sub_paths = glob( $upload_dir . '/*', GLOB_ONLYDIR );
    foreach ( $sub_paths as $sub_path ) {
        $files = glob( $sub_path . '/*.pdf' );
        foreach ( $files as $file ) {
            // ok: claude.php.wordpress.file-write-delete.request-filename-unlink-no-auth-check
            wp_delete_file( $file );
        }
    }
}
