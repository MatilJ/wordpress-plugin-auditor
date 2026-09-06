<?php

class Cloud_Download_Handler {

	public function download( $id ) {
		// ruleid: claude.php.wordpress.info-disclosure.upload-basedir-static-filename-write
		$upload_dir = wp_upload_dir();
		$file_content = $this->fetch_remote_item( $id );

		$file_name        = 'plugin-tmp.json';
		$_temp_file_name  = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . $file_name;
		$_temp_file_url   = $upload_dir['baseurl'] . DIRECTORY_SEPARATOR . $file_name;

		$handle = fopen( $_temp_file_name, 'x+' );
		fwrite( $handle, $file_content );
		fclose( $handle );

		return $_temp_file_url;
	}

	public function export_cache( $data ) {
		// ruleid: claude.php.wordpress.info-disclosure.upload-basedir-static-filename-write
		$upload_dir = wp_upload_dir();
		file_put_contents( $upload_dir['basedir'] . '/' . 'export-cache.json', $data );
	}

	public function download_randomized( $id ) {
		$upload_dir = wp_upload_dir();
		$file_content = $this->fetch_remote_item( $id );

		// ok: claude.php.wordpress.info-disclosure.upload-basedir-static-filename-write
		$file_name       = wp_generate_password( 20, false );
		$_temp_file_name = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . $file_name;

		$handle = fopen( $_temp_file_name, 'x+' );
		fwrite( $handle, $file_content );
		fclose( $handle );
	}

	public function download_session_scoped( $id, $session_id ) {
		$upload_dir = wp_upload_dir();
		$file_content = $this->fetch_remote_item( $id );

		// ok: claude.php.wordpress.info-disclosure.upload-basedir-static-filename-write
		$_temp_file_name = $upload_dir['basedir'] . '/' . $session_id . '/' . 'item.json';

		$handle = fopen( $_temp_file_name, 'x+' );
		fwrite( $handle, $file_content );
		fclose( $handle );
	}

	public function write_debug_log( $message ) {
		// ok: claude.php.wordpress.info-disclosure.upload-basedir-static-filename-write
		$log_dir = WP_CONTENT_DIR . '/mydebug/';
		$handle  = fopen( $log_dir . 'debug.log', 'a' );
		fwrite( $handle, $message );
		fclose( $handle );
	}

	private function fetch_remote_item( $id ) {
		return '{}';
	}
}
