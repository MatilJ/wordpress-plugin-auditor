<?php

function evf_merge_old_files_vuln1( $field_submit, $data ) {
	if ( isset( $field_submit['old_files'] ) ) {
		// ruleid: claude.php.wordpress.file-write-delete.decoded-file-reference-array-map-merge-unchecked
		$old_data = array_map(
			function ( $file ) {
				$decoded = json_decode( $file, true );

				return is_array( $decoded ) ? $decoded : array();
			},
			$field_submit['old_files']
		);

		$data = array_merge( $data, $old_data );
	}

	return $data;
}

function evf_merge_resume_files_vuln2( $submitted, $entry_data ) {
	if ( isset( $submitted['resume_files'] ) ) {
		// ruleid: claude.php.wordpress.file-write-delete.decoded-file-reference-array-map-merge-unchecked
		$decoded_items = array_map(
			function ( $item ) {
				$decoded = json_decode( $item, true );

				return is_array( $decoded ) ? $decoded : [];
			},
			$submitted['resume_files']
		);

		$entry_data = array_merge( $entry_data, $decoded_items );
	}

	return $entry_data;
}

// ok: claude.php.wordpress.file-write-delete.decoded-file-reference-array-map-merge-unchecked
function evf_merge_old_files_fixed( $field_submit, $data ) {
	if ( isset( $field_submit['old_files'] ) && is_array( $field_submit['old_files'] ) ) {
		$validated_old_data = array();

		foreach ( $field_submit['old_files'] as $file ) {
			$decoded = json_decode( $file, true );

			if ( ! is_array( $decoded ) || empty( $decoded['value'] ) || ! is_string( $decoded['value'] ) ) {
				continue;
			}

			$resolved_path = evf_resolve_uploads_file_from_url( $decoded['value'] );

			if ( false === $resolved_path ) {
				continue;
			}

			$decoded['value']     = esc_url_raw( $decoded['value'] );
			$validated_old_data[] = $decoded;
		}

		if ( ! empty( $validated_old_data ) ) {
			$data = array_merge( $data, $validated_old_data );
		}
	}

	return $data;
}

// ok: claude.php.wordpress.file-write-delete.decoded-file-reference-array-map-merge-unchecked
function evf_get_form_meta( $entry_id ) {
	global $wpdb;

	$meta = get_post_meta( $entry_id, '_evf_form_fields', true );

	return is_array( $meta ) ? $meta : array();
}
