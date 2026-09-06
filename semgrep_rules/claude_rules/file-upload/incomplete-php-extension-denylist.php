<?php
// Real-world pre-fix shape (CVE-2026-3459): a dedicated "not allowed
// extensions" function already blocks 'php' and 'phtml' but forgot the
// '.pht' alias (still PHP-executable on many hosts).
function dnd_cf7_not_allowed_ext() {
	// ruleid: claude.php.wordpress.file-upload.incomplete-php-extension-denylist
	return array( 'svg', 'phar', 'php', 'php3', 'php4', 'phtml', 'exe', 'js' );
}

function dnd_upload_cf7_upload() {
	$blacklist_types = dnd_cf7_not_allowed_ext();
	$ext             = strtolower( pathinfo( $_FILES['upload-file']['name'], PATHINFO_EXTENSION ) );

	if ( in_array( $ext, $blacklist_types, true ) ) {
		wp_send_json_error( 'Invalid file type.' );
	}

	move_uploaded_file( $_FILES['upload-file']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . $_FILES['upload-file']['name'] );
}

// Variable-assignment shape of the same gap: same class of denylist, this
// time assigned to a local variable rather than returned from a helper.
function plugin_validate_upload_extension( $ext ) {
	// ruleid: claude.php.wordpress.file-upload.incomplete-php-extension-denylist
	$not_allowed_extensions = array( 'php', 'phtml', 'exe', 'sh', 'cgi' );

	return ! in_array( $ext, $not_allowed_extensions, true );
}

// Fixed shape: official CVE-2026-3459 patch adds 'pht' (and the other
// missed PHP-version aliases) alongside the pre-existing entries.
function dnd_cf7_not_allowed_ext_fixed() {
	// ok: claude.php.wordpress.file-upload.incomplete-php-extension-denylist
	return array( 'svg', 'phar', 'php', 'php3', 'php4', 'pht', 'php5', 'php7', 'php8', 'phtml', 'exe', 'js' );
}

// No 'php'/'phtml' entries at all — a denylist targeting a different
// concern (archive/script extensions) rather than PHP execution, so the
// rule's specific "claims to block PHP but missed an alias" signal does
// not apply here.
function plugin_disallowed_archive_ext() {
	// ok: claude.php.wordpress.file-upload.incomplete-php-extension-denylist
	return array( 'zip', 'rar', 'tar', 'gz' );
}

// WP DB-read pattern: unrelated read-only lookup, included as a
// non-firing baseline alongside the upload cases above.
function plugin_get_upload_log_row( $id ) {
	global $wpdb;
	// ok: claude.php.wordpress.file-upload.incomplete-php-extension-denylist
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}plugin_uploads WHERE id = %d", $id ), ARRAY_A );
}
