<?php
// Real-world pre-fix shape (CVE-2025-14800): a custom "move to upload dir"
// helper copies an arbitrary source file into a permanent upload directory
// via $wp_filesystem->copy() with a random-hashed unique filename, but never
// checks the source file's type before persisting it.
function plugin_move_file_to_upload( $file_path ) {
	global $wp_filesystem;
	WP_Filesystem();

	$upload_dir       = wp_upload_dir()['basedir'] . '/plugin-uploads';
	$new_file_name    = wp_unique_filename( $upload_dir, basename( $file_path ) );
	$destination_path = path_join( $upload_dir, $new_file_name );

	// ruleid: claude.php.wordpress.upload.wp-filesystem-copy-no-filetype-check
	$moved = $wp_filesystem->copy( $file_path, $destination_path, true );

	if ( ! $moved ) {
		return false;
	}

	return $destination_path;
}

// Bare-statement shape: $wp_filesystem->move() with no validation at all.
function plugin_finalize_import( $tmp_path, $target_path ) {
	global $wp_filesystem;
	// ruleid: claude.php.wordpress.upload.wp-filesystem-copy-no-filetype-check
	$wp_filesystem->move( $tmp_path, $target_path, true );
}

// Fixed shape: wp_check_filetype() gates the copy, matching the official
// CVE-2025-14800 patch.
function plugin_move_file_to_upload_fixed( $file_path ) {
	$validate = wp_check_filetype( $file_path );
	if ( ! $validate['type'] || preg_match( '#^[a-zA-Z0-9+.-]+://#', $file_path ) ) {
		die( 'File type is not allowed' );
	}

	global $wp_filesystem;
	WP_Filesystem();

	$upload_dir       = wp_upload_dir()['basedir'] . '/plugin-uploads';
	$new_file_name    = wp_unique_filename( $upload_dir, basename( $file_path ) );
	$destination_path = path_join( $upload_dir, $new_file_name );

	// ok: claude.php.wordpress.upload.wp-filesystem-copy-no-filetype-check
	$moved = $wp_filesystem->copy( $file_path, $destination_path, true );

	return $moved ? $destination_path : false;
}

// wp_handle_upload() present in the same function: standard WP validation path.
function plugin_handle_upload_wp_way( $file ) {
	$overrides = array( 'test_form' => false );
	$movefile  = wp_handle_upload( $file, $overrides );

	global $wp_filesystem;
	// ok: claude.php.wordpress.upload.wp-filesystem-copy-no-filetype-check
	$wp_filesystem->copy( $movefile['file'], $movefile['file'] . '.bak', true );
}

// WP DB-read pattern: unrelated read-only lookup, included as a non-firing
// baseline alongside the upload cases above.
function plugin_get_import_row( $id ) {
	global $wpdb;
	// ok: claude.php.wordpress.upload.wp-filesystem-copy-no-filetype-check
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}plugin_imports WHERE id = %d", $id ), ARRAY_A );
}
