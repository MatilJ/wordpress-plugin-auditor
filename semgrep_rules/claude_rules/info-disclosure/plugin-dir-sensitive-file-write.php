<?php

function write_debug_log( $message ) {
    $log_path = plugin_dir_path( __FILE__ ) . 'logs/debug.log';
    // ruleid: claude.php.wordpress.info-disclosure.plugin-dir-sensitive-file-write
    file_put_contents( $log_path, $message . "\n", FILE_APPEND );
}

function write_export_file( $data ) {
    $path = WP_CONTENT_DIR . '/uploads/plugin-export/data.csv';
    // ruleid: claude.php.wordpress.info-disclosure.plugin-dir-sensitive-file-write
    file_put_contents( $path, $data );
}

function open_log_file() {
    $file = WP_PLUGIN_DIR . '/my-plugin/error.log';
    // ruleid: claude.php.wordpress.info-disclosure.plugin-dir-sensitive-file-write
    $handle = fopen( $file, 'a' );
    return $handle;
}

// ok: claude.php.wordpress.info-disclosure.plugin-dir-sensitive-file-write
function write_temp_file( $data ) {
    $path = sys_get_temp_dir() . '/plugin-temp.log';
    file_put_contents( $path, $data );
}

// ok: claude.php.wordpress.info-disclosure.plugin-dir-sensitive-file-write
function write_outside_webroot( $data ) {
    $path = '/var/log/plugin/debug.log';
    file_put_contents( $path, $data );
}
