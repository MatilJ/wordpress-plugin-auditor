<?php

// Test cases for claude.php.wordpress.access-control.nonce-only-file-export-no-capability-check

class MyPlugin_Tools {

	// TP: if-wrapped negated nonce check only, no capability/login check,
	// before a Content-Disposition: attachment download.
	// ruleid: claude.php.wordpress.access-control.nonce-only-file-export-no-capability-check
	public static function export_system_info() {
		if ( ! wp_verify_nonce( $_POST['export_nonce'], 'export_sysinfo' ) ) {
			return;
		}

		header( 'Content-Type: text/plain' );
		header( 'Content-Disposition: attachment; filename="system-info.txt"' );
		echo self::build_report();
		exit;
	}

	// TP: bare check_admin_referer() call, no current_user_can()/is_user_logged_in().
	// ruleid: claude.php.wordpress.access-control.nonce-only-file-export-no-capability-check
	public static function download_debug_log() {
		check_admin_referer( 'download_debug_log' );

		header( 'Content-Disposition: attachment; filename="debug.log"' );
		echo file_get_contents( WP_CONTENT_DIR . '/debug.log' );
		exit;
	}

	// FP: nonce check plus current_user_can() and is_user_logged_in() — properly gated.
	// ok: claude.php.wordpress.access-control.nonce-only-file-export-no-capability-check
	public static function export_system_info_fixed() {
		if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $_POST['export_nonce'], 'export_sysinfo' ) ) {
			return;
		}

		header( 'Content-Type: text/plain' );
		header( 'Content-Disposition: attachment; filename="system-info.txt"' );
		echo self::build_report();
		exit;
	}

	// FP: nonce check plus a capability check gate — admin-only.
	// ok: claude.php.wordpress.access-control.nonce-only-file-export-no-capability-check
	public static function download_debug_log_fixed() {
		check_admin_referer( 'download_debug_log' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized.' );
		}

		header( 'Content-Disposition: attachment; filename="debug.log"' );
		echo file_get_contents( WP_CONTENT_DIR . '/debug.log' );
		exit;
	}

	// Scope note: a normal DB read reached via a WP core wrapper — no download
	// header at all, falls outside this rule's scope (no annotation needed).
	public static function get_settings_row() {
		global $wpdb;
		if ( ! wp_verify_nonce( $_POST['nonce'], 'get_settings' ) ) {
			return;
		}
		return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}myplugin_settings" );
	}

	public static function build_report() {
		return 'report';
	}
}
