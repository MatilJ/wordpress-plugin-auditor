<?php

function save_signature_upload( $id, $data ) {
    $upload_dir = wp_upload_dir();
    $dirTmp = $upload_dir['basedir'] . '/form_uploads/signatures/';
    if ( !is_dir( $dirTmp ) ) {
        // ruleid: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        mkdir( $dirTmp, 0777 );
    }
    $file_name = 'signature-' . rand( 0, 9999999999 ) . '.png';
    file_put_contents( $dirTmp . $file_name, $data );
}

function save_export_archive( $slug ) {
    $upload_dir = wp_upload_dir();
    $export_dir = $upload_dir['basedir'] . '/' . $slug . '/exports/';
    if ( !file_exists( $export_dir ) ) {
        // ruleid: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        mkdir( $export_dir, 0777, true );
    }
    return $export_dir;
}

function save_signature_upload_patched( $id, $data ) {
    $upload_dir = wp_upload_dir();
    $dirTmp = $upload_dir['basedir'] . '/form_uploads/signatures/';
    if ( !is_dir( $dirTmp ) ) {
        // ok: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        mkdir( $dirTmp, 0777 );
        $indexfile = fopen( $dirTmp . 'index.html', 'w' );
        fclose( $indexfile );
        $htaccessfile = fopen( $dirTmp . '.htaccess', 'w' );
        fwrite( $htaccessfile, 'deny from all' );
        fclose( $htaccessfile );
    }
    $file_name = 'signature-' . uniqid() . '.png';
    file_put_contents( $dirTmp . $file_name, $data );
}

function ensure_plugin_cache_dir_outside_webroot() {
    $cache_dir = WP_CONTENT_DIR . '/../wf-cache/';
    if ( !is_dir( $cache_dir ) ) {
        // ok: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        mkdir( $cache_dir, 0700 );
    }
    return $cache_dir;
}

function setup_log_directory_wp_mkdir_p() {
    $upload_dir = wp_upload_dir();
    $log_dir = $upload_dir['basedir'] . '/plugin-logs/';
    if ( ! file_exists( $log_dir ) ) {
        // ruleid: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        wp_mkdir_p( $log_dir );
    }
    return $log_dir;
}

function setup_log_directory_wp_mkdir_p_with_file_put_contents_guard() {
    $upload_dir = wp_upload_dir();
    $log_dir = $upload_dir['basedir'] . '/plugin-logs/';
    if ( ! file_exists( $log_dir ) ) {
        // ok: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        wp_mkdir_p( $log_dir );
        file_put_contents( $log_dir . '.htaccess', "Order deny,allow\nDeny from all\n" );
        file_put_contents( $log_dir . 'index.php', '<?php // Silence is golden' );
    }
    return $log_dir;
}

function save_settings_backup_wp_filesystem( $data ) {
    global $wp_filesystem;
    $upload_dir = wp_upload_dir();
    $dir = trailingslashit( $upload_dir['basedir'] ) . 'MyPlugin/';
    if ( ! $wp_filesystem->is_dir( $dir ) ) {
        // ruleid: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        $wp_filesystem->mkdir( $dir );
    }
    $wp_filesystem->put_contents( $dir . 'settings_backup.json', $data );
}

function save_settings_backup_wp_filesystem_patched( $data ) {
    global $wp_filesystem;
    $upload_dir = wp_upload_dir();
    $dir = trailingslashit( $upload_dir['basedir'] ) . 'MyPlugin/';
    if ( ! $wp_filesystem->is_dir( $dir ) ) {
        // ok: claude.php.wordpress.info-disclosure.upload-dir-mkdir-no-index-protection
        $wp_filesystem->mkdir( $dir );
        $wp_filesystem->put_contents( $dir . 'index.php', "<?php\n// Silence is golden.\n" );
        $wp_filesystem->put_contents( $dir . '.htaccess', "Order deny,allow\nDeny from all\n" );
    }
    $wp_filesystem->put_contents( $dir . 'settings_backup.json', $data );
}
