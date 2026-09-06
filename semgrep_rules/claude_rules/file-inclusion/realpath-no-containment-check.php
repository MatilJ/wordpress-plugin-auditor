<?php

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// Shape 1: realpath()'d result assigned to a variable, only existence/
// readability re-checked afterward -- no containment check anywhere.
// Match is reported at the enclosing function's declaration line (the
// rule's pattern spans the whole "function $FUNC(...) { ... }" template).
// ruleid: claude.php.wordpress.file.realpath-no-containment-check
function serve_cached_asset( $allowed_directory, $file_path ) {
    $full_path = $allowed_directory . '/' . $file_path;
    $full_path = realpath( $full_path );
    if ( !$full_path || !is_readable( $full_path ) ) {
        wp_die();
    }
    readfile( $full_path );
}

// Shape 2: realpath() applied inline at the include site, no guard at all.
// ruleid: claude.php.wordpress.file.realpath-no-containment-check
function render_layout_vulnerable( $base_dir, $atts ) {
    $tpl = $base_dir . '/layout/' . $atts['layout'] . '.php';
    include realpath( $tpl );
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// Containment check present, comparing the realpath()'d result against the
// same base directory -- the real fix shape.
function serve_cached_asset_fixed( $allowed_directory, $file_path ) {
    $full_path = $allowed_directory . '/' . $file_path;
    // ok: claude.php.wordpress.file.realpath-no-containment-check
    $full_path = realpath( $full_path );
    if ( !$full_path || strpos( $full_path, $allowed_directory ) !== 0 ) {
        wp_die();
    }
    readfile( $full_path );
}

// Already-validated-base + scandir()-enumerated-filename idiom: the caller-
// supplied $dir is itself canonicalized and strpos()-checked against a fixed
// allowed root BEFORE the loop; each per-file $path is built only from that
// already-validated $dir plus a filename scandir() itself enumerated (not
// request-controlled), so the later per-file realpath() cannot escape
// containment even though the check never re-examines $path/$real_path
// directly.
function delete_page_cache_dir( $dir ) {
    if ( empty( $dir ) ) {
        return;
    }
    $real_dir = realpath( $dir );
    $real_allowed_dir = realpath( CACHE_ROOT_DIR );
    if ( $real_dir === false || $real_allowed_dir === false ) {
        return;
    }
    if ( strpos( $real_dir, $real_allowed_dir ) !== 0 ) {
        return;
    }
    if ( is_dir( $dir ) ) {
        foreach ( scandir( $dir ) as $file ) {
            if ( $file === '.' || $file === '..' ) {
                continue;
            }
            // ok: claude.php.wordpress.file.realpath-no-containment-check
            $path = $dir . $file;
            $real_path = realpath( $path );
            if ( $real_path !== false ) {
                unlink( $real_path );
            }
        }
    }
}

// Allow-list check guards the realpath()-wrapped include.
function render_layout_fixed( $base_dir, $atts ) {
    $tpl = $base_dir . '/layout/' . $atts['layout'] . '.php';
    if ( in_array( $tpl, [ $base_dir . '/layout/layout-1.php', $base_dir . '/layout/layout-2.php' ], true ) ) {
        // ok: claude.php.wordpress.file.realpath-no-containment-check
        include realpath( $tpl );
    }
}
