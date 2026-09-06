<?php
/**
 * Test fixture for claude.php.wordpress.auth.unauthenticated-plugin-theme-install
 * Covers the install/activate sinks NOT owned by unauthenticated-plugin-activation
 * (which handles activate_plugin()/deactivate_plugins()): the WP_Upgrader classes,
 * activate_plugins() (plural), and switch_theme().
 *
 * NOTE: the rule matches whole function bodies, so findings are reported at the
 * `function` line — annotations sit directly above each function.
 */

// ---- VULNERABLE: Plugin_Upgrader instantiation, no capability check ----
// ruleid: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function bad_plugin_upgrader( $request ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
	$upgrader = new \Plugin_Upgrader();
	$upgrader->install( $request->get_param( 'url' ) );
}

// ---- VULNERABLE: Theme_Upgrader instantiation, no capability check ----
// ruleid: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function bad_theme_upgrader() {
	$up = new Theme_Upgrader();
	$up->install( $_POST['pkg'] );
}

// ---- VULNERABLE: activate_plugins() (plural) with attacker input ----
// ruleid: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function bad_activate_plugins() {
	activate_plugins( $_POST['plugins'] );
}

// ---- VULNERABLE: switch_theme() with attacker input ----
// ruleid: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function bad_switch_theme() {
	switch_theme( $_GET['theme'] );
}

// ---- OK: capability-gated (early return) ----
// ok: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function ok_plugin_upgrader_capped( $request ) {
	if ( ! current_user_can( 'install_plugins' ) ) {
		return;
	}
	$upgrader = new \Plugin_Upgrader();
	$upgrader->install( $request->get_param( 'url' ) );
}

// ok: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function ok_activate_plugins_capped() {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		wp_die();
	}
	activate_plugins( $_POST['plugins'] );
}

// ok: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function ok_switch_theme_capped() {
	if ( ! current_user_can( 'switch_themes' ) ) {
		return;
	}
	switch_theme( $_GET['theme'] );
}

// ---- OK: super admin gate ----
// ok: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function ok_super_admin() {
	if ( is_super_admin() ) {
		activate_plugins( $_POST['plugins'] );
	}
}

// ---- OK: hardcoded target (bundled companion / core theme), not attacker-controlled ----
// ok: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function ok_hardcoded_plugin() {
	activate_plugins( 'companion/companion.php' );
}

// ok: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function ok_hardcoded_theme() {
	switch_theme( 'twentytwentyfour' );
}

// ---- OK: capability-gated via a bare ALL-CAPS constant instead of a string
// literal (e.g. define('PLUGIN_ADMIN_CAP', 'manage_options')) — the constant's
// value is fixed at development time, not attacker-influenceable. ----
// ok: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function ok_plugin_upgrader_constant_cap( $request ) {
	if ( current_user_can( PLUGIN_ADMIN_CAP ) ) {
		$upgrader = new \Plugin_Upgrader();
		$upgrader->install( $request->get_param( 'url' ) );
	}
}

// ---- VULNERABLE: capability argument is an attacker-influenceable variable,
// not a fixed constant — must still be flagged (confirms the constant exception
// does not swallow the variable case). ----
// ruleid: claude.php.wordpress.auth.unauthenticated-plugin-theme-install
function bad_plugin_upgrader_variable_cap( $request, $required_cap ) {
	if ( current_user_can( $required_cap ) ) {
		$upgrader = new \Plugin_Upgrader();
		$upgrader->install( $request->get_param( 'url' ) );
	}
}
