<?php

// ── Vulnerable: real pre-fix shape — mail-attachment containment filter ────
function filter_attachments_vulnerable( $attachments ) {
    $upload_dir = wp_upload_dir();
    if ( ! empty( $upload_dir['basedir'] ) ) {
        foreach ( $attachments as $key => $attachment ) {
            // ruleid: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
            if ( 0 !== strpos( $attachment, $upload_dir['basedir'] ) ) {
                unset( $attachments[ $key ] );
            }
        }
    }
    return $attachments;
}

// ── Vulnerable: reversed operator/order + str_starts_with variant ──────────
function is_within_uploads_vulnerable( $path ) {
    $base_dir = wp_upload_dir()['basedir'];
    // ruleid: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( strpos( $path, $base_dir ) === 0 ) {
        return true;
    }
    // ruleid: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( ! str_starts_with( $path, $base_dir ) ) {
        return false;
    }
    return true;
}

// ── Safe: the real fix — realpath() canonicalization before the check ──────
function filter_attachments_fixed( $attachments ) {
    $upload_dir     = wp_upload_dir();
    $basedir_real   = realpath( $upload_dir['basedir'] );
    $basedir_prefix = trailingslashit( wp_normalize_path( $basedir_real ) );
    foreach ( $attachments as $key => $attachment ) {
        $path_real = realpath( $attachment );
        // ok: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
        if ( false === $path_real || 0 !== strpos( wp_normalize_path( $path_real ), $basedir_prefix ) ) {
            unset( $attachments[ $key ] );
        }
    }
    return $attachments;
}

// ── Safe: unrelated strpos usage against a non-directory string (WP DB read) ─
function get_widget_option_value( $meta_key ) {
    global $wpdb;
    // ok: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( 0 === strpos( $meta_key, 'widget_' ) ) {
        return $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $meta_key ) );
    }
    return null;
}

// ── Vulnerable: CVE-2025-8141 shape — normalizer-prefixed base-dir name with
// no "_dir" suffix ("$normalized_uploads"), guarding a delete call ─────────
function delete_associated_files_vulnerable( $postid, $post ) {
    $files_meta          = get_post_meta( $postid, 'files', true );
    $upload_dir          = wp_upload_dir();
    $normalized_uploads  = wp_normalize_path( $upload_dir['basedir'] );

    global $wp_filesystem;
    WP_Filesystem();

    foreach ( $files_meta as $file_key => $file_data ) {
        $normalized_path = wp_normalize_path( $file_data['path'] );
        if (
            // ruleid: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
            0 === strpos( $normalized_path, $normalized_uploads ) &&
            $wp_filesystem->exists( $normalized_path )
        ) {
            $wp_filesystem->delete( $normalized_path );
        }
    }
}

// ── Safe: widened $BASE regex must not match an unrelated "uploaded by"
// identifier that merely contains "upload" as a substring of a different word
function is_uploaded_by_current_user( $meta_value ) {
    $uploader_marker = 'uploaded_by:';
    // ok: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( 0 === strpos( $meta_value, $uploader_marker ) ) {
        return true;
    }
    return false;
}

// ── Vulnerable: CVE-2026-42737 shape — property-access base-dir
// ("$this->attachmentsPath") guarding a file-deletion call. The camelCase
// suffix ("Path") sits immediately after "attachments" with no separator,
// so a trailing-\b regex alternative would also miss this — only a fully
// unanchored substring test closes it.
class Chat_Attachment_Store_Vulnerable {
    public $attachmentsPath;

    public function removeAttachment( $attachment ) {
        $filePath = $attachment->getPath();
        // ruleid: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
        if ( strpos( $filePath, $this->attachmentsPath ) !== 0 ) {
            return false;
        }
        return unlink( $filePath );
    }
}

// ── Safe: same property-access shape as above, but with the real fix —
// realpath() resolves ".." segments before the prefix comparison runs.
class Chat_Attachment_Store_Fixed {
    public $attachmentsPath;

    public function removeAttachment( $attachment ) {
        $filePath = $attachment->getPath();
        $filePath = realpath( $filePath );
        // ok: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
        if ( ! $filePath || strpos( $filePath, $this->attachmentsPath ) !== 0 ) {
            return false;
        }
        return unlink( $filePath );
    }
}

// ── Vulnerable: CVE-2025-68912 shape — realpath() applied ONLY to the base
// directory before an attacker-controlled remainder is concatenated onto the
// already-resolved result, then the concatenation is prefix-checked against
// the same unresolved base. realpath() never sees the traversal sequences in
// $uid_dir because they are appended after it already ran.
function hdf_check_dir_safe_vulnerable( $uid_dir ) {
    $upload_dir = wp_upload_dir();
    $upload_dir = $upload_dir['basedir'] . '/hdforms/';

    $real_path = realpath( $upload_dir ) . $uid_dir;

    // ruleid: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( $real_path && strpos( $real_path, $upload_dir ) === 0 ) {
        return true;
    }
    return false;
}

// ── Vulnerable: same shape, reversed strpos operand check ("!== 0" fail-open
// style) guarding an unlink()/rmdir() delete sink directly.
function purge_upload_subdir_vulnerable( $dir ) {
    $base_dir  = wp_upload_dir()['basedir'] . '/plugin-cache/';
    $real_path = realpath( $base_dir ) . $dir;
    // ruleid: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( 0 !== strpos( $real_path, $base_dir ) ) {
        return false;
    }
    array_map( 'unlink', glob( "$real_path/*.*" ) );
    return rmdir( $real_path );
}

// ── Safe: relative-path-for-display idiom (mirrors WP core's own private
// _wp_relative_upload_path()) — the matched prefix is stripped off the same
// variable via str_replace() and returned as a plain string; no file-read/
// write/delete/serve operation is gated on the result. Confirmed FP:
// shortpixel-image-optimiser 6.5.5 UtilHelper::getRelativeUploadPath().
function get_relative_upload_path_display_only( $path ) {
    $new_path = $path;
    $uploads  = wp_get_upload_dir();
    // ok: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( 0 === strpos( $new_path, $uploads['basedir'] ) ) {
        $new_path = str_replace( $uploads['basedir'], '', $new_path );
        $new_path = ltrim( $new_path, '/' );
    }
    return $new_path;
}

// ── Safe: CVE-2025-68912 shape, but the concatenated result is re-resolved
// with realpath() before the prefix check runs, so ".." segments in $uid_dir
// are canonicalized before comparison — the check is now meaningful.
function hdf_check_dir_safe_fixed( $uid_dir ) {
    $upload_dir = wp_upload_dir();
    $upload_dir = $upload_dir['basedir'] . '/hdforms/';

    $real_path = realpath( $upload_dir ) . $uid_dir;
    $real_path = realpath( $real_path );

    // ok: claude.php.wordpress.file.strpos-prefix-containment-no-realpath
    if ( $real_path && strpos( $real_path, $upload_dir ) === 0 ) {
        return true;
    }
    return false;
}
