<?php
/**
 * Test fixture for claude.php.wordpress.csrf.plugin-theme-install-without-nonce
 * Capability present + install/activate sink + NO nonce => CSRF (CVE-2025-25101).
 * The rule flags at the current_user_can() call, so annotations sit above it.
 */

// ---- VULNERABLE: cap, install sink, no nonce ----
function csrf_bad_install() {
	// ruleid: claude.php.wordpress.csrf.plugin-theme-install-without-nonce
	if ( ! current_user_can( 'install_plugins' ) ) {
		return;
	}
	$up = new \Plugin_Upgrader();
	$up->install( $_GET['url'] );
}

function csrf_bad_activate() {
	// ruleid: claude.php.wordpress.csrf.plugin-theme-install-without-nonce
	if ( ! current_user_can( 'activate_plugins' ) ) {
		wp_die();
	}
	activate_plugin( $_GET['plugin'] );
}

function csrf_bad_switch_theme() {
	// ruleid: claude.php.wordpress.csrf.plugin-theme-install-without-nonce
	if ( current_user_can( 'switch_themes' ) ) {
		switch_theme( $_GET['theme'] );
	}
}

// ---- OK: nonce verified ----
function csrf_ok_install() {
	check_admin_referer( 'install_action' );
	// ok: claude.php.wordpress.csrf.plugin-theme-install-without-nonce
	if ( ! current_user_can( 'install_plugins' ) ) {
		return;
	}
	$up = new \Plugin_Upgrader();
	$up->install( $_GET['url'] );
}

function csrf_ok_activate_nonce() {
	if ( ! wp_verify_nonce( $_GET['_wpnonce'], 'act' ) ) {
		wp_die();
	}
	// ok: claude.php.wordpress.csrf.plugin-theme-install-without-nonce
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	activate_plugin( $_GET['plugin'] );
}

// ---- OK: capability check but NO install/activate sink (out of scope) ----
function csrf_ok_no_sink() {
	// ok: claude.php.wordpress.csrf.plugin-theme-install-without-nonce
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	update_option( 'foo', $_GET['v'] );
}

// ---- OK: nonce verified via a custom auth-wrapper call rather than a direct
// wp_verify_nonce()/check_admin_referer() call in this function's own body ----
function csrf_ok_wrapper_nonce() {
	__::isAuthentic( 'wpdmappnonce', NONCE_KEY, WPDM_ADMIN_CAP );
	// ok: claude.php.wordpress.csrf.plugin-theme-install-without-nonce
	if ( current_user_can( WPDM_ADMIN_CAP ) ) {
		$up = new \Plugin_Upgrader();
		$up->install( 'https://downloads.wordpress.org/plugin/companion.zip' );
	}
}
