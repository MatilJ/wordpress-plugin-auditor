<?php

// Vulnerable shape: extension is read from the original filename but never
// checked against an allow-list/MIME sniff before the file is written.
function save_attachment( $content, $original_name ) {
	$upload_dir = get_upload_folder();
	$extension  = pathinfo( $original_name, PATHINFO_EXTENSION );
	$hash       = hash( 'md5', $content );
	$new_name   = substr( $hash, 0, 16 ) . '-' . basename( $original_name );
	$new_path   = trailingslashit( $upload_dir ) . $new_name;
	global $wp_filesystem;
	// ruleid: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
	$result = $wp_filesystem->put_contents( $new_path, $content, FS_CHMOD_FILE );
	return $result ? $new_path : false;
}

class Import_Handler {
	public function store_uploaded_file( $content, $original_name ) {
		$extension  = pathinfo( $original_name, PATHINFO_EXTENSION );
		$dest_name  = uniqid() . '-' . basename( $original_name );
		$dest_path  = WP_CONTENT_DIR . '/uploads/import/' . $dest_name;
		// ruleid: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
		file_put_contents( $dest_path, $content );
		return $dest_path;
	}
}

class Import_Handler_Fixed {
	// Real-world fix shape: a private helper (any name) that allow-lists the
	// extension and sniffs the real MIME type, gated by a negated early return.
	private function is_allowed_type( $extension, $content ) {
		return in_array( $extension, array( 'jpg', 'png', 'pdf' ), true );
	}

	public function store_uploaded_file( $content, $original_name ) {
		$extension = pathinfo( $original_name, PATHINFO_EXTENSION );
		if ( ! $this->is_allowed_type( $extension, $content ) ) {
			return false;
		}
		$dest_name = uniqid() . '-' . basename( $original_name );
		$dest_path = WP_CONTENT_DIR . '/uploads/import/' . $dest_name;
		// ok: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
		file_put_contents( $dest_path, $content );
		return $dest_path;
	}
}

function save_attachment_checked( $content, $original_name ) {
	$upload_dir = get_upload_folder();
	$extension  = pathinfo( $original_name, PATHINFO_EXTENSION );
	$filetype   = wp_check_filetype_and_ext( $original_name, $original_name );
	if ( empty( $filetype['ext'] ) ) {
		return false;
	}
	$new_name = uniqid() . '-' . basename( $original_name );
	$new_path = trailingslashit( $upload_dir ) . $new_name;
	global $wp_filesystem;
	// ok: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
	$result = $wp_filesystem->put_contents( $new_path, $content, FS_CHMOD_FILE );
	return $result;
}

function log_uploaded_file_record( $post_id ) {
	global $wpdb;
	// ok: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
	$row = $wpdb->get_row( "SELECT filename FROM {$wpdb->prefix}suremails_logs WHERE id = " . intval( $post_id ), ARRAY_A );
	return $row;
}

// Vulnerable shape (CVE-2025-11391 class): a client-side image-cropping
// widget posts a base64 data-URI plus the original filename under an
// 'org'/'orig'/'original' key; the filename is used as-is -- no
// pathinfo()/basename() extraction, no type check -- before a save
// delegate call persists the decoded content.
function save_cropped_field_image( $cropped_fields, $posted_data ) {
	foreach ( $cropped_fields as $field_id => $values ) {
		$image_data = $values['cropped'];
		$file_name  = isset( $values['org'] ) ? $values['org'] : '';
		// ruleid: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
		save_data_url_to_image( $image_data, $file_name );
	}
}

function save_avatar_crop_upload( $payload ) {
	$avatar_data = isset( $payload['data'] ) ? $payload['data'] : '';
	$file_name   = isset( $payload['original'] ) ? $payload['original'] : 'avatar.png';
	$upload_dir  = get_upload_folder();
	$raw         = base64_decode( preg_replace( '#^data:image/\w+;base64,#i', '', $avatar_data ) );
	$dest        = trailingslashit( $upload_dir ) . $file_name;
	// ruleid: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
	file_put_contents( $dest, $raw );
}

function save_avatar_crop_upload_fixed( $payload ) {
	$avatar_data   = isset( $payload['data'] ) ? $payload['data'] : '';
	$file_name     = isset( $payload['original'] ) ? $payload['original'] : 'avatar.png';
	$allowed_types = array( 'jpg', 'png' );
	$upload_dir    = get_upload_folder();
	$file_type     = wp_check_filetype_and_ext( trailingslashit( $upload_dir ) . $file_name, $file_name );
	if ( ! in_array( $file_type['ext'], $allowed_types, true ) ) {
		return false;
	}
	$raw  = base64_decode( preg_replace( '#^data:image/\w+;base64,#i', '', $avatar_data ) );
	$dest = trailingslashit( $upload_dir ) . $file_name;
	// ok: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
	file_put_contents( $dest, $raw );
}

// Vulnerable shape (CVE-2026-14894 class): a data-URI string is decoded and
// written via the raw fopen()/fwrite() handle API. The destination basename
// is used exactly as submitted -- no basename()/pathinfo() extraction, no
// sanitize_file_name(), no extension allow-list, and no check that the
// decoded bytes actually are the expected file type -- before the write.
function submit_form_save_generated_file( $upload_dir, $field ) {
	$img_data = str_replace( ' ', '+', $field['datauristring'] );
	$img_data = substr( $img_data, strpos( $img_data, ',' ) + 1 );
	$img_data = base64_decode( $img_data );
	$basename = $field['value'];
	$filename = trailingslashit( $upload_dir['path'] ) . $basename;
	// ruleid: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
	$file = fopen( $filename, 'w' );
	fwrite( $file, $img_data );
	fclose( $file );
}

// Fixed shape: forced safe extension, decoded-content signature check, and a
// realpath()-based containment check confining the write to the upload dir
// -- wrapped in the try/catch the real patch uses around this decode+write
// branch (the guard is scoped to this enclosing try{}, not the whole
// function -- see the rule's containment-guard comment for why).
function submit_form_save_generated_file_fixed( $upload_dir, $field ) {
	try {
		$img_data = str_replace( ' ', '+', $field['datauristring'] );
		$img_data = substr( $img_data, strpos( $img_data, ',' ) + 1 );
		$img_data = base64_decode( $img_data );
		$stem     = trim( preg_replace( '/\.[^.]*$/', '', sanitize_file_name( wp_basename( $field['value'] ) ) ), '.-_' );
		$basename = $stem . '.pdf';
		if ( '%PDF-' !== substr( $img_data, 0, 5 ) ) {
			throw new Exception( 'invalid upload' );
		}
		$base_dir = realpath( $upload_dir['path'] );
		$filename = trailingslashit( $base_dir ) . $basename;
		if ( 0 !== strpos( trailingslashit( realpath( dirname( $filename ) ) ), trailingslashit( $base_dir ) ) ) {
			throw new Exception( 'invalid upload' );
		}
		// ok: claude.php.wordpress.file-upload.write-original-extension-no-typecheck
		$file = fopen( $filename, 'wb' );
		fwrite( $file, $img_data );
		fclose( $file );
	} catch ( Exception $e ) {
		return false;
	}
}
