<?php
/**
 * Test fixture for claude.php.wordpress.auth.nopriv-plugin-theme-install (join mode).
 * Finding is reported at the callback function line, so ruleid/ok sit above it.
 */

// ---- VULNERABLE: nopriv + Plugin_Upgrader install, no cap/nonce ----
add_action( 'wp_ajax_nopriv_n1_install', 'n1_install_cb' );
// ruleid: claude.php.wordpress.auth.nopriv-plugin-theme-install
function n1_install_cb() {
	$u = new \Plugin_Upgrader();
	$u->install( $_POST['url'] );
}

// ---- VULNERABLE: admin_post_nopriv + activate_plugin ----
add_action( 'admin_post_nopriv_n1_act', array( $obj, 'n1_act_cb' ) );
// ruleid: claude.php.wordpress.auth.nopriv-plugin-theme-install
function n1_act_cb() {
	activate_plugin( $_POST['p'] );
}

// ---- VULNERABLE: nopriv + manual download_url + unzip_file install ----
add_action( 'wp_ajax_nopriv_n1_unzip', 'n1_unzip_cb' );
// ruleid: claude.php.wordpress.auth.nopriv-plugin-theme-install
function n1_unzip_cb() {
	$tmp = download_url( $_POST['url'] );
	unzip_file( $tmp, WP_PLUGIN_DIR );
}

// ---- OK: nopriv but capability-checked ----
add_action( 'wp_ajax_nopriv_n1_safe', 'n1_safe_cb' );
// ok: claude.php.wordpress.auth.nopriv-plugin-theme-install
function n1_safe_cb() {
	if ( ! current_user_can( 'install_plugins' ) ) {
		return;
	}
	$u = new \Plugin_Upgrader();
	$u->install( $_POST['url'] );
}

// ---- OK: authenticated wp_ajax_ (not nopriv) ----
add_action( 'wp_ajax_n1_auth', 'n1_auth_cb' );
// ok: claude.php.wordpress.auth.nopriv-plugin-theme-install
function n1_auth_cb() {
	$u = new \Plugin_Upgrader();
	$u->install( $_POST['url'] );
}
