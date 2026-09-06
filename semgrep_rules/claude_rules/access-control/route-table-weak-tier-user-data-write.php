<?php
// Test cases for claude.php.wordpress.access-control.route-table-weak-tier-user-data-write

class Route_Table_Weak_Tier_Test {

	/**
	 * Real-world shape: short-array route table, weak 'user' tier gates a
	 * data-mutating callback (CVE-2025-48164 class — before the fix that
	 * changed the tier to 'admin').
	 */
	public function register_routes_vulnerable_short_array() {
		// ruleid: claude.php.wordpress.access-control.route-table-weak-tier-user-data-write
		$routes['update-user-data'] = [
			'method'              => 'POST',
			'callback'            => [ Some_Router::get_instance(), 'update_user_data' ],
			'permission_callback' => 'user',
		];
		return $routes;
	}

	/**
	 * Variant naming + long array() syntax + double quotes + a different
	 * weak tier token ('subscriber') gating an account-mutating callback.
	 */
	public function register_routes_vulnerable_long_array() {
		// ruleid: claude.php.wordpress.access-control.route-table-weak-tier-user-data-write
		$routes["change-account-role"] = array(
			"method"              => "POST",
			"callback"            => array( $this, "change_account_data" ),
			"permission_callback" => "subscriber",
		);
		return $routes;
	}

	/**
	 * The fix: same endpoint, same callback, tier raised to 'admin'.
	 */
	public function register_routes_fixed_admin_tier() {
		// ok: claude.php.wordpress.access-control.route-table-weak-tier-user-data-write
		$routes['update-user-data'] = [
			'method'              => 'POST',
			'callback'            => [ Some_Router::get_instance(), 'update_user_data' ],
			'permission_callback' => 'admin',
		];
		return $routes;
	}

	/**
	 * Weak 'user' tier is fine here because the callback is read-only —
	 * the method name carries no mutation verb.
	 */
	public function register_routes_read_only_user_tier() {
		// ok: claude.php.wordpress.access-control.route-table-weak-tier-user-data-write
		$routes['get-user-profile'] = [
			'method'              => 'GET',
			'callback'            => [ Some_Router::get_instance(), 'get_user_profile' ],
			'permission_callback' => 'user',
		];
		return $routes;
	}

	/**
	 * permission_callback is an actual capability-checked closure, not a
	 * bare symbolic tier string — does not match the pattern shape at all.
	 */
	public function register_routes_capability_closure() {
		// ok: claude.php.wordpress.access-control.route-table-weak-tier-user-data-write
		$routes['update-user-data'] = [
			'method'              => 'POST',
			'callback'            => [ Some_Router::get_instance(), 'update_user_data' ],
			'permission_callback' => function() {
				return current_user_can( 'manage_options' );
			},
		];
		return $routes;
	}
}
