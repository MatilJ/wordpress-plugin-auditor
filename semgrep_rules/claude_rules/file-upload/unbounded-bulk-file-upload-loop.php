<?php

// ruleid: claude.php.wordpress.upload.unbounded-bulk-file-upload-loop
function process_uploads_vulnerable( $files, $key, $post_id = 0 ) {
	$attachment_ids = array();
	foreach ( $files['name'] as $id => $value ) {
		if ( $files['name'][ $id ] ) {
			$_FILES[ $key ] = array(
				'name'     => $files['name'][ $id ],
				'type'     => $files['type'][ $id ],
				'tmp_name' => $files['tmp_name'][ $id ],
				'error'    => $files['error'][ $id ],
				'size'     => $files['size'][ $id ],
			);
			$attachment_id = media_handle_upload( $key, $post_id );
			if ( ! is_wp_error( $attachment_id ) ) {
				$attachment_ids[] = $attachment_id;
			}
		}
	}
	return $attachment_ids;
}

// ruleid: claude.php.wordpress.upload.unbounded-bulk-file-upload-loop
function bulk_sideload_no_limit( $items ) {
	$results = array();
	foreach ( $items as $item ) {
		$results[] = wp_handle_sideload( $item, array( 'test_form' => false ) );
	}
	return $results;
}

// ok: claude.php.wordpress.upload.unbounded-bulk-file-upload-loop
function process_uploads_fixed( $files, $key, $post_id = 0 ) {
	$max_files_per_upload = apply_filters( 'wooccm_max_files_per_upload', 10 );
	if ( count( $files['name'] ) > $max_files_per_upload ) {
		return array();
	}
	$attachment_ids = array();
	foreach ( $files['name'] as $id => $value ) {
		if ( $files['name'][ $id ] ) {
			$_FILES[ $key ] = array(
				'name'     => $files['name'][ $id ],
				'type'     => $files['type'][ $id ],
				'tmp_name' => $files['tmp_name'][ $id ],
				'error'    => $files['error'][ $id ],
				'size'     => $files['size'][ $id ],
			);
			$attachment_id = media_handle_upload( $key, $post_id );
			if ( ! is_wp_error( $attachment_id ) ) {
				$attachment_ids[] = $attachment_id;
			}
		}
	}
	return $attachment_ids;
}

// ok: claude.php.wordpress.upload.unbounded-bulk-file-upload-loop
function normal_wp_db_read( $post_id ) {
	global $wpdb;
	$rows = $wpdb->get_results(
		$wpdb->prepare( "SELECT * FROM {$wpdb->postmeta} WHERE post_id = %d", $post_id )
	);
	foreach ( $rows as $row ) {
		error_log( $row->meta_key );
	}
	return $rows;
}
