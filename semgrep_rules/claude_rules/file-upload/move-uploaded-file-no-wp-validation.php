<?php
// Real-world pre-fix shape (CVE-2025-9216): if-guarded move_uploaded_file(),
// with only sanitize_file_name() applied to the name - no extension/mime check.
function se_import_csv() {
	if ( ! isset( $_FILES['file'] ) ) {
		wp_send_json_error( 'No file uploaded.' );
	}

	$file     = $_FILES['file'];
	$folder   = get_upload_dir() . '/csv/';
	$filename = sanitize_file_name( $file['name'] );
	$target   = trailingslashit( $folder ) . $filename;

	// ruleid: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
	if ( ! move_uploaded_file( $file['tmp_name'], $target ) ) {
		wp_send_json_error( 'Failed to move uploaded file.' );
	}
}

// Bare-statement shape: no guard, no validation at all.
function plugin_handle_upload() {
	$target = WP_CONTENT_DIR . '/uploads/imports/' . $_FILES['file']['name'];
	// ruleid: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
	move_uploaded_file( $_FILES['file']['tmp_name'], $target );
}

// Fixed shape: extension allow-list + wp_check_filetype_and_ext() gate the
// move, matching the official CVE-2025-9216 patch.
function se_import_csv_fixed() {
	$file = $_FILES['file'];
	$ext  = strtolower( pathinfo( $file['name'], PATHINFO_EXTENSION ) );
	if ( 'csv' !== $ext ) {
		wp_send_json_error( 'Only CSV files are allowed.' );
	}

	$filename = sanitize_file_name( wp_basename( $file['name'] ) );
	$filetype = wp_check_filetype_and_ext( $file['tmp_name'], $filename, [ 'csv' => 'text/csv' ] );
	if ( ! isset( $filetype['ext'] ) || 'csv' !== $filetype['ext'] ) {
		wp_send_json_error( 'Invalid file type.' );
	}

	$target = trailingslashit( get_upload_dir() . '/csv/' ) . $filename;
	// ok: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
	if ( ! move_uploaded_file( $file['tmp_name'], $target ) ) {
		wp_send_json_error( 'Failed to move uploaded file.' );
	}
}

// wp_handle_upload() present in the same function: standard WP validation path.
function plugin_handle_upload_wp_way() {
	$overrides = [ 'test_form' => false ];
	$movefile  = wp_handle_upload( $_FILES['file'], $overrides );
	// ok: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
	move_uploaded_file( $_FILES['file']['tmp_name'], $movefile['file'] );
}

// WP DB-read pattern: unrelated read-only lookup near the import feature,
// included as a non-firing baseline alongside the upload cases above.
function plugin_get_import_row( $id ) {
	global $wpdb;
	// ok: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}se_imports WHERE id = %d", $id ), ARRAY_A );
}

// Large-denylist shape (CVE-2026-5364): a custom extension check backed by a
// long PHP-adjacent denylist (php/phtml/phar/... 30+ entries) still MUST fire
// — it is a string-based pathinfo() extension test, not real WP validation,
// and this exact CVE proves such denylists are bypassable.
function plugin_is_file_type_valid( $file_types, $file ) {
	static $blacklist = [ 'php', 'php3', 'php4', 'php5', 'phtml', 'pht', 'phar', 'phpt', 'shtml', 'htaccess' ];
	$ext = strtolower( pathinfo( $file['name'], PATHINFO_EXTENSION ) );
	$allowed = array_map( 'trim', explode( '|', strtolower( $file_types ) ) );
	return ( in_array( $ext, $allowed, true ) && ! in_array( $ext, $blacklist, true ) );
}
function plugin_ajax_file_uploads() {
	$file = $_FILES['file'];
	$type = sanitize_text_field( $_REQUEST['type'] );
	$ext  = pathinfo( $file['name'], PATHINFO_EXTENSION );
	$target = trailingslashit( get_upload_dir() ) . uniqid() . '.' . $ext;
	if ( ! plugin_is_file_type_valid( $type, $file ) ) {
		wp_send_json_error( 'This file type is not allowed.' );
	}
	// ruleid: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
	move_uploaded_file( $file['tmp_name'], $target );
}

// Standalone dispatcher-script shape (top-level, no enclosing function at
// all): a direct-request action dispatcher (if/in_array + switch on a raw
// request key) invoked directly instead of routing through admin-ajax.php.
// No nonce/capability gate, no extension/type check anywhere in the script.
$upload_action = $_REQUEST['action'];
if ( in_array( $upload_action, array( 'do_upload' ), true ) ) {
	switch ( $upload_action ) {
		case 'do_upload':
			$upload_dir = $_POST['path'];
			$dest = $upload_dir . basename( $_FILES['uploadfile']['name'] );
			// ruleid: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
			move_uploaded_file( $_FILES['uploadfile']['tmp_name'], $dest );
			break;
	}
}

// Same top-level shape, no if/switch wrapper, no validation anywhere.
$upload_dir2 = $_POST['dir'];
$dest2 = $upload_dir2 . $_FILES['file2']['name'];
// ruleid: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
move_uploaded_file( $_FILES['file2']['tmp_name'], $dest2 );

// Top-level script, but wp_check_filetype_and_ext() validates the upload
// before the move — should NOT fire.
$upload_dir3 = $_POST['dir3'];
$filetype3   = wp_check_filetype_and_ext( $_FILES['file3']['tmp_name'], $_FILES['file3']['name'] );
$dest3       = $upload_dir3 . '.' . $filetype3['ext'];
// ok: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
move_uploaded_file( $_FILES['file3']['tmp_name'], $dest3 );

// Top-level script routed through wp_handle_upload() — standard WP path.
$overrides4 = array( 'test_form' => false );
$movefile4  = wp_handle_upload( $_FILES['file4'], $overrides4 );
// ok: claude.php.wordpress.upload.move-uploaded-file-no-wp-validation
move_uploaded_file( $_FILES['file4']['tmp_name'], $movefile4['file'] );
