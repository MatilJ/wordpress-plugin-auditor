<?php

// Test cases for claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename

// Real-world shape: ternary-wrapped fallback around get_bloginfo(), then
// sanitize_title() + a fixed extension — the exact _prepare_directory_name()
// idiom that produces a fully offline-computable export archive filename.
function prepare_export_filename() {
    $site_title = ! empty( get_bloginfo( 'name' ) ) ? get_bloginfo( 'name' ) : 'package';
    // ruleid: claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename
    return sanitize_title( $site_title ) . '-myplugin';
}

function prepare_backup_zip_name() {
    // ruleid: claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename
    return sanitize_title( get_bloginfo( 'name' ) ) . '.zip';
}

function prepare_export_filename_from_home_url() {
    $slug = home_url();
    // ruleid: claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename
    return sanitize_title( $slug ) . '-backup';
}

function prepare_export_filename_sanitize_file_name() {
    $site_title = ! empty( get_bloginfo( 'name' ) ) ? get_bloginfo( 'name' ) : 'package';
    // ruleid: claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename
    return sanitize_file_name( $site_title ) . '.zip';
}

// --- TRUE NEGATIVES ---

function prepare_export_filename_with_random_suffix() {
    $site_title = get_bloginfo( 'name' );
    // ok: claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename
    return sanitize_title( $site_title ) . '-' . wp_generate_password( 12, false );
}

function prepare_export_filename_admin_supplied() {
    $custom_name = jupiterx_post( 'data' )['filename'];
    // ok: claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename
    return sanitize_title( $custom_name ) . '-myplugin';
}

function prepare_cache_key_not_public_metadata() {
    $user_email = wp_get_current_user()->user_email;
    // ok: claude.php.wordpress.info-disclosure.public-metadata-derived-predictable-filename
    return sanitize_title( $user_email ) . '.cache';
}
