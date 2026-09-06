<?php
// claude.php.wordpress.file-upload.download-url-no-filetype-check test cases
// Confirmed TP source: Breeze 2.4.4 class-breeze-cache-cronjobs.php:138-141
// fetch_gravatar_from_remote() downloads a remote URL and moves the temp file
// to wp-content/cache/breeze-extra/gravatars/ without checking the extension.

// ── Vulnerable patterns ───────────────────────────────────────────────────────

function fetch_and_store_no_check( string $url, string $cache_dir ): void {
	global $wp_filesystem;
	$filename = basename( wp_parse_url( $url, PHP_URL_PATH ) );
	// ruleid: claude.php.wordpress.file-upload.download-url-no-filetype-check
	$tmpfile = download_url( $url );
	if ( ! is_wp_error( $tmpfile ) ) {
		$wp_filesystem->move( $tmpfile, $cache_dir . $filename, true );
	}
}

function import_remote_asset_no_check( string $url, string $dest ): bool {
	// ruleid: claude.php.wordpress.file-upload.download-url-no-filetype-check
	$tmpfile = download_url( $url );
	if ( is_wp_error( $tmpfile ) ) {
		return false;
	}
	return rename( $tmpfile, $dest );
}

// ── Safe patterns ─────────────────────────────────────────────────────────────

function fetch_with_filetype_check_after_download( string $url, string $cache_dir ): bool {
	global $wp_filesystem;
	$filename = basename( wp_parse_url( $url, PHP_URL_PATH ) );
	// ok: claude.php.wordpress.file-upload.download-url-no-filetype-check
	$tmpfile = download_url( $url );
	if ( is_wp_error( $tmpfile ) ) {
		return false;
	}
	// wp_check_filetype() validates extension between download and move.
	$filetype = wp_check_filetype( $filename );
	if ( empty( $filetype['ext'] ) || ! in_array( $filetype['ext'], array( 'jpg', 'jpeg', 'png', 'gif', 'webp' ), true ) ) {
		@unlink( $tmpfile );
		return false;
	}
	$wp_filesystem->move( $tmpfile, $cache_dir . $filename, true );
	return true;
}

function fetch_with_ext_and_mime_check( string $url, string $cache_dir ): bool {
	global $wp_filesystem;
	$filename = basename( wp_parse_url( $url, PHP_URL_PATH ) );
	// ok: claude.php.wordpress.file-upload.download-url-no-filetype-check
	$tmpfile = download_url( $url );
	if ( is_wp_error( $tmpfile ) ) {
		return false;
	}
	// wp_check_filetype_and_ext() validates both extension and magic-byte MIME type.
	$filetype_data = wp_check_filetype_and_ext( $tmpfile, $filename );
	if ( empty( $filetype_data['ext'] ) ) {
		@unlink( $tmpfile );
		return false;
	}
	return rename( $tmpfile, $cache_dir . $filename );
}
