<?php
// Test cases for claude.php.wordpress.access-control.optional-auth-flag-skips-password-check

// ---- TRUE POSITIVE 1: real-world shape (CVE-2025-67953 class) ----
// Password check only runs inside an elseif gated by a flag that defaults
// to true; when false, the get_user_by() lookup alone is returned as the
// authenticated user.
function bookacti_validate_login( $login_values, $require_authentication = true ) {
	$user_login = ! empty( $login_values['email'] ) ? $login_values['email'] : '';
	$user       = $user_login ? get_user_by( is_email( $user_login ) ? 'email' : 'login', $user_login ) : null;

	$return_array = array( 'status' => 'failed' );

	if ( ! $user ) {
		$return_array['error'] = 'user_not_found';
	}
	// ruleid: claude.php.wordpress.access-control.optional-auth-flag-skips-password-check
	else if ( $require_authentication ) {
		$user = wp_authenticate( $user->user_email, $login_values['password'] );
	}

	return is_a( $user, 'WP_User' ) ? $user : $return_array;
}

// ---- TRUE POSITIVE 2: generalized variant, different flag/sink names ----
// Bare-call-statement form (no reassignment) and wp_check_password() sink.
function plugin_login_with_optional_check( $creds, $verify_password = true ) {
	$account = get_user_by( 'email', $creds['email'] );
	if ( ! $account ) {
		return false;
	}

	// ruleid: claude.php.wordpress.access-control.optional-auth-flag-skips-password-check
	if ( $verify_password ) {
		wp_check_password( $creds['password'], $account->user_pass, $account->ID );
	}

	return $account;
}

// ---- FALSE POSITIVE (ok): the actual fix — verification is unconditional ----
// The optional parameter was removed entirely; password is always checked,
// defaulting to an empty string that wp_authenticate() will properly reject.
function bookacti_validate_login_fixed( $login_values ) {
	$user_login = ! empty( $login_values['email'] ) ? $login_values['email'] : '';
	$user       = $user_login ? get_user_by( is_email( $user_login ) ? 'email' : 'login', $user_login ) : null;

	$return_array = array( 'status' => 'failed' );

	if ( ! $user ) {
		$return_array['error'] = 'user_not_found';
	}
	else {
		// ok: claude.php.wordpress.access-control.optional-auth-flag-skips-password-check
		$password = ! empty( $login_values['password'] ) ? $login_values['password'] : '';
		$user     = wp_authenticate( $user->user_email, $password );
	}

	return is_a( $user, 'WP_User' ) ? $user : $return_array;
}

// ---- FALSE POSITIVE (ok): flag gates only a non-auth side effect ----
// "remember" does not match the auth/password/login-flag name regex, and it
// does not gate the credential check itself.
function plugin_login_with_remember_flag( $creds, $remember = true ) {
	$account = get_user_by( 'email', $creds['email'] );
	$user    = wp_authenticate( $creds['email'], $creds['password'] );

	if ( $remember ) {
		// ok: claude.php.wordpress.access-control.optional-auth-flag-skips-password-check
		setcookie( 'remember_me', '1', time() + 3600 * 24 * 30 );
	}

	return $user;
}

// ---- FALSE POSITIVE (ok): ordinary WP DB read, unrelated to authentication ----
function get_recent_bookings_report( $limit = 10 ) {
	global $wpdb;
	// ok: claude.php.wordpress.access-control.optional-auth-flag-skips-password-check
	$results = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}bookings ORDER BY id DESC LIMIT %d", $limit ) );
	return $results;
}
