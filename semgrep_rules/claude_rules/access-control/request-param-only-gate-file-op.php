<?php
// Test file: claude.php.wordpress.access-control.request-param-only-gate-file-op

// ── Vulnerable patterns ────────────────────────────────────────────────────────

class Font_Compat {

    // VULNERABLE: bare $_GET equality routing gate, no auth check, recursive delete
    // plus a config-file overwrite, both inside the same gated constructor.
    public function __construct() {
        if ( empty( $_GET['page'] ) || 'demo' !== $_GET['page'] || empty( $_GET['settings'] ) || 'reset' !== $_GET['settings'] ) {
            return;
        }
        $fonts_folder_path = get_stylesheet_directory() . '/assets/fonts/demo';
        if ( is_dir( $fonts_folder_path ) ) {
            // ruleid: claude.php.wordpress.access-control.request-param-only-gate-file-op
            $this->fs->delete( $fonts_folder_path, true, 'd' );
        }
        $theme_json_path = get_stylesheet_directory() . '/theme.json';
        $data             = json_decode( file_get_contents( $theme_json_path ), true );
        // ruleid: claude.php.wordpress.access-control.request-param-only-gate-file-op
        file_put_contents( $theme_json_path, wp_json_encode( $data ) );
    }
}

// VULNERABLE: $_REQUEST routing gate feeding unlink(), no auth check.
function reset_cache_file() {
    if ( isset( $_REQUEST['reset_cache'] ) && 'yes' === $_REQUEST['reset_cache'] ) {
        $cache_file = WP_CONTENT_DIR . '/cache/demo-plugin/data.cache';
        // ruleid: claude.php.wordpress.access-control.request-param-only-gate-file-op
        unlink( $cache_file );
    }
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: current_user_can() gate present before the file operation.
function admin_reset_cache_file() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'no' );
    }
    if ( isset( $_REQUEST['reset_cache'] ) && 'yes' === $_REQUEST['reset_cache'] ) {
        $cache_file = WP_CONTENT_DIR . '/cache/demo-plugin/data.cache';
        // ok: claude.php.wordpress.access-control.request-param-only-gate-file-op
        unlink( $cache_file );
    }
}

// SAFE: nonce verified via check_ajax_referer() before the file operation.
function ajax_reset_cache_file() {
    check_ajax_referer( 'demo_reset_nonce', 'nonce' );
    if ( isset( $_REQUEST['reset_cache'] ) ) {
        $cache_file = WP_CONTENT_DIR . '/cache/demo-plugin/data.cache';
        // ok: claude.php.wordpress.access-control.request-param-only-gate-file-op
        unlink( $cache_file );
    }
}
