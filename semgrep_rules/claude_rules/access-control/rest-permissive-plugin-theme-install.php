<?php
/**
 * Test fixture for claude.php.wordpress.auth.rest-permissive-plugin-theme-install
 * (join mode). Finding is reported at the callback method line.
 * Models GutenKit CVE-2024-9234 (unpatched = vuln, 2.4.6 cap check = ok).
 */

// ---- VULNERABLE: permissive REST + manual download_url/unzip_file install ----
class R3Vuln {
	public function __construct() {
		register_rest_route( 'x/v1', 'install', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'do_install_vuln' ),
			'permission_callback' => '__return_true',
		) );
	}
	// ruleid: claude.php.wordpress.auth.rest-permissive-plugin-theme-install
	public function do_install_vuln( $request ) {
		$tmp = download_url( $request->get_param( 'url' ) );
		unzip_file( $tmp, WP_PLUGIN_DIR );
	}
}

// ---- VULNERABLE: permissive REST (short-array options) + Plugin_Upgrader ----
class R3Vuln2 {
	public function __construct() {
		register_rest_route( 'x/v1', 'install3', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'do_upgrader_vuln' ],
			'permission_callback' => '__return_true',
		] );
	}
	// ruleid: claude.php.wordpress.auth.rest-permissive-plugin-theme-install
	public function do_upgrader_vuln( $request ) {
		$u = new \Plugin_Upgrader();
		$u->install( $request->get_param( 'url' ) );
	}
}

// ---- OK: permissive route but callback checks capability (GutenKit 2.4.6 patch) ----
class R3Safe {
	public function __construct() {
		register_rest_route( 'x/v1', 'install2', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'do_install_safe' ),
			'permission_callback' => '__return_true',
		) );
	}
	// ok: claude.php.wordpress.auth.rest-permissive-plugin-theme-install
	public function do_install_safe( $request ) {
		if ( ! current_user_can( 'install_plugins' ) ) {
			return;
		}
		$tmp = download_url( $request->get_param( 'url' ) );
		unzip_file( $tmp, WP_PLUGIN_DIR );
	}
}

// ---- OK: install callback but route has a real (non-permissive) permission_callback ----
class R3Safe2 {
	public function __construct() {
		register_rest_route( 'x/v1', 'install4', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'do_install_gated' ),
			'permission_callback' => array( $this, 'check_perms' ),
		) );
	}
	public function check_perms() {
		return current_user_can( 'install_plugins' );
	}
	// ok: claude.php.wordpress.auth.rest-permissive-plugin-theme-install
	public function do_install_gated( $request ) {
		$u = new \Plugin_Upgrader();
		$u->install( $request->get_param( 'url' ) );
	}
}
