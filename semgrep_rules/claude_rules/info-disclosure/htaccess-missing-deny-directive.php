<?php

function init_backup_archive_dir_fopen( $archive_dir ) {
    $file_name = $archive_dir . '/.htaccess';
    if ( ! file_exists( $file_name ) ) {
        $htaccess_file = @fopen( $file_name, 'w' );
        $htoutput = 'Options -Indexes';
        // ruleid: claude.php.wordpress.info-disclosure.htaccess-missing-deny-directive
        @fwrite( $htaccess_file, $htoutput );
        @fclose( $htaccess_file );
    }
}

function init_export_dir( $export_dir ) {
    $file_name = $export_dir . '/.htaccess';
    $htoutput  = 'Options -Indexes';
    // ruleid: claude.php.wordpress.info-disclosure.htaccess-missing-deny-directive
    file_put_contents( $file_name, $htoutput );
}

function init_backup_archive_dir_patched( $archive_dir ) {
    $file_name = $archive_dir . '/.htaccess';
    $htoutput  = "Options -Indexes\n# Block direct HTTP access to all files\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order Allow,Deny\n    Deny from all\n</IfModule>";
    // ok: claude.php.wordpress.info-disclosure.htaccess-missing-deny-directive
    file_put_contents( $file_name, $htoutput );
}

function write_normal_log( $log_dir, $message ) {
    $file_name = $log_dir . '/debug.log';
    // ok: claude.php.wordpress.info-disclosure.htaccess-missing-deny-directive
    file_put_contents( $file_name, $message, FILE_APPEND );
}

function init_log_dir_legacy_apache22_only( $log_dir ) {
    // Path built inline at the call site, only the content is pre-assigned —
    // the real-world shape used by File_Logger-style class-based loggers.
    $htaccess_content = "Order deny,allow\nDeny from all\n";
    // ruleid: claude.php.wordpress.info-disclosure.htaccess-missing-deny-directive
    file_put_contents( $log_dir . '.htaccess', $htaccess_content );
}

function init_export_dir_legacy_order_allow_deny( $export_dir ) {
    $file_name = $export_dir . '/.htaccess';
    $htoutput = "order allow,deny\ndeny from all";
    // ruleid: claude.php.wordpress.info-disclosure.htaccess-missing-deny-directive
    file_put_contents( $file_name, $htoutput );
}

function init_log_dir_apache24_only( $upload_dir ) {
    $log_dir = $upload_dir['basedir'] . '/plugin-logs/';
    $file_name = $log_dir . '.htaccess';
    $htaccess_content = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n";
    // ok: claude.php.wordpress.info-disclosure.htaccess-missing-deny-directive
    file_put_contents( $file_name, $htaccess_content );
}
