<?php
/**
 * Test fixture for claude.php.wordpress.csrf.file-write-capability-only-no-nonce
 * Capability present + file-write sink + NO nonce => CSRF (CVE-2026-11784).
 * The rule flags at the current_user_can() call, so annotations sit above it.
 */

// ---- VULNERABLE: cap check, raw file-write sink, no nonce ----
function csrf_bad_raw_write() {
	$id = (int) $_POST['attachment_id'];
	// ruleid: claude.php.wordpress.csrf.file-write-capability-only-no-nonce
	if ( ! current_user_can( 'edit_post', $id ) ) {
		wp_send_json_error( 'nope' );
	}
	move_uploaded_file( $_FILES['file']['tmp_name'], get_attached_file( $id ) );
}

// ---- VULNERABLE: cap check, OOP replacer built directly from $_FILES, no nonce ----
function csrf_bad_replacer_object() {
	$id = (int) $_POST['attachment_id'];
	// ruleid: claude.php.wordpress.csrf.file-write-capability-only-no-nonce
	if ( ! current_user_can( 'edit_post', $id ) ) {
		wp_send_json_error( 'nope' );
	}
	$replacer = new Attachment_Replace( $id, $_FILES['file'] );
	$replaced = $replacer->replace();
}

// ---- OK: nonce verified before the capability check ----
function csrf_ok_nonce_then_cap() {
	// ok: claude.php.wordpress.csrf.file-write-capability-only-no-nonce
	if ( ! check_ajax_referer( 'replace_media_nonce', 'nonce', false ) ) {
		wp_send_json_error( 'bad nonce' );
	}
	$id = absint( $_POST['attachment_id'] ?? 0 );
	if ( ! current_user_can( 'edit_post', $id ) ) {
		wp_send_json_error( 'nope' );
	}
	$replacer = new Attachment_Replace( $id, $_FILES['file'] );
	$replaced = $replacer->replace();
}

// ---- OK: capability check but no file-write sink (out of scope) ----
function csrf_ok_no_sink() {
	// ok: claude.php.wordpress.csrf.file-write-capability-only-no-nonce
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	global $wpdb;
	$rows = $wpdb->get_results( "SELECT ID FROM {$wpdb->posts} WHERE post_status = 'publish'" );
	update_option( 'last_checked', time() );
}
