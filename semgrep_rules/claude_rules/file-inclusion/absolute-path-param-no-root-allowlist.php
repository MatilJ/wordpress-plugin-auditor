<?php

class SanityCheck {
    public static function noControlChars($s) {
        return $s;
    }
    public static function pathWithoutDirectoryTraversal($s) {
        return str_replace('..', '', $s);
    }
    public static function absPathExistsAndIsFile($path) {
        if (!is_file($path)) {
            throw new Exception('not found');
        }
        return $path;
    }
}

function getSourceDocRoot() {
    if (isset($_GET['xsource'])) {
        $xsrc = SanityCheck::noControlChars($_GET['xsource']);
        // ruleid: claude.php.wordpress.file-inclusion.absolute-path-param-no-root-allowlist
        return SanityCheck::absPathExistsAndIsFile(substr($xsrc, 1));
    }
    return null;
}

function serveRequestedFile() {
    $path = $_GET['file'];
    // ruleid: claude.php.wordpress.file-inclusion.absolute-path-param-no-root-allowlist
    return file_get_contents($path);
}

function getSourceDocRootContained() {
    if (isset($_GET['xsource'])) {
        $xsrc = SanityCheck::noControlChars($_GET['xsource']);
        $candidate = substr($xsrc, 1);
        $real = realpath($candidate);
        if ($real === false || strpos($real, ABSPATH) !== 0) {
            throw new Exception('outside root');
        }
        // ok: claude.php.wordpress.file-inclusion.absolute-path-param-no-root-allowlist
        return SanityCheck::absPathExistsAndIsFile($real);
    }
    return null;
}

function serveRequestedFileByName() {
    $upload_dir = wp_upload_dir();
    $name = basename($_GET['file']);
    $path = $upload_dir['basedir'] . '/' . $name;
    // ok: claude.php.wordpress.file-inclusion.absolute-path-param-no-root-allowlist
    return file_get_contents($path);
}

// SAFE: the tainted value is checked with strict in_array(..., true)
// membership against an existing-values array (here, log filenames the
// filesystem already contains) before the sink runs — the attacker can only
// select an already-existing filename, no traversal possible regardless of
// the array's own origin.
function showLogFile() {
    $log_files     = scandir( IG_LOG_DIR );
    $log_file_name = sanitize_text_field( $_POST['log_file'] );
    if ( in_array( $log_file_name, $log_files, true ) ) {
        // ok: claude.php.wordpress.file-inclusion.absolute-path-param-no-root-allowlist
        return file_get_contents( IG_LOG_DIR . $log_file_name );
    }
    return null;
}

// SAFE: $_POST['progressID'] is used only as the KEY argument of
// get_transient() — the returned value is the server-computed upload path
// stored earlier by a separate set_transient() call, never a reflection of
// the key's own content.
function importChunkFromProgressId() {
    $progress_id = $_POST['progressID'];
    $file_name = get_transient( $progress_id );
    if ( $file_name ) {
        // ok: claude.php.wordpress.file-inclusion.absolute-path-param-no-root-allowlist
        $file = fopen( $file_name, 'r' );
    }
    return null;
}

function getSourceRelativeToDocRoot() {
    if (isset($_GET['xsource-rel'])) {
        $xsrcRel = SanityCheck::noControlChars($_GET['xsource-rel']);
        $srcRel = SanityCheck::pathWithoutDirectoryTraversal(substr($xsrcRel, 1));
        // ok: claude.php.wordpress.file-inclusion.absolute-path-param-no-root-allowlist
        return SanityCheck::absPathExistsAndIsFile('/var/www/html' . '/' . $srcRel);
    }
    return null;
}
