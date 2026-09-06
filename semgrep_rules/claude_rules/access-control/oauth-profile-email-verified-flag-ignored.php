<?php
// Test cases for claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored

// === TRUE POSITIVES — profile ->email trusted for login, ->emailVerified never checked ===

// Vulnerable: resolves the account by the OAuth profile's raw email with no
// verified-flag check anywhere in the function.
// ruleid: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function social_login_callback_no_verify_check() {
	$adapter = $hybridauth->getAdapter( $provider );
	$userProfile = $adapter->getUserProfile();

	$data = [
		'email' => $userProfile->email,
		'identifier' => $userProfile->identifier,
	];

	$user = get_user_by( 'email', sanitize_email( $data['email'] ) );
	if ( $user ) {
		wp_set_auth_cookie( $user->ID, true );
	}
}

// Vulnerable: same shape, but the trust decision is email_exists() instead
// of a direct get_user_by() call.
// ruleid: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function social_register_or_login_no_verify_check() {
	$adapter = $hybridauth->getAdapter( $provider );
	$userProfile = $adapter->getUserProfile();

	$email = sanitize_email( $userProfile->email );

	if ( email_exists( $email ) ) {
		$user = get_user_by( 'email', $email );
		wp_set_current_user( $user->ID );
	}
}

// === FALSE POSITIVES — the profile's own verified-email flag is checked ===

// Safe: rejects the flow when the provider never verified this email
// (the actual upstream fix shape).
// ok: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function social_login_callback_with_verify_check() {
	$adapter = $hybridauth->getAdapter( $provider );
	$userProfile = $adapter->getUserProfile();

	if ( empty( $userProfile->emailVerified ) ) {
		wp_die( 'Email not verified by provider.' );
	}

	$data = [
		'email' => $userProfile->email,
	];

	$user = get_user_by( 'email', sanitize_email( $data['email'] ) );
	if ( $user ) {
		wp_set_auth_cookie( $user->ID, true );
	}
}

// Safe: identity resolved from a stable per-provider user meta key, not the
// raw OAuth-claimed email at all — a normal WP DB-read pattern.
// ok: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function social_login_by_stored_provider_id() {
	$adapter = $hybridauth->getAdapter( $provider );
	$userProfile = $adapter->getUserProfile();

	$users = get_users( array(
		'meta_key' => 'social_provider_id',
		'meta_value' => $userProfile->identifier,
	) );

	if ( $users ) {
		wp_set_auth_cookie( $users[0]->ID, true );
	}
}

// === Variant 2: per-provider raw-JSON profile normalizer (no adapter) ===

// Vulnerable: this provider's branch assigns the normalized email straight
// from the decoded OAuth API response with no verified-flag check, even
// though a sibling branch in the same normalizer (not shown) may check one
// for a different provider — the neutralizer must be per-statement.
function normalize_profile_data( $profileData, $provider ) {
	$temp = array();
	if ( $provider == 'exampleprovider' ) {
		// ruleid: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
		$temp['email'] = isset( $profileData->response ) && isset( $profileData->response->email )
			? sanitize_email( $profileData->response->email )
			: '';
	}
	return $temp;
}

// Vulnerable: object-property (not array-key) normalized-output variant.
function normalize_profile_object( $profileData, $provider ) {
	$out = new stdClass();
	if ( $provider == 'exampleprovider' ) {
		// ruleid: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
		$out->email = sanitize_email( $profileData->email );
	}
	return $out;
}

// Safe: the provider's own verified-flag is checked in the SAME assignment
// before the email is trusted (the real upstream fix shape for providers
// that do expose a verified flag).
// ok: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function normalize_profile_data_with_verified_check( $profileData, $provider ) {
	$temp = array();
	if ( $provider == 'exampleprovider' ) {
		$temp['email'] = isset( $profileData->verified ) && $profileData->verified == 1 && isset( $profileData->email )
			? sanitize_email( $profileData->email )
			: '';
	}
	return $temp;
}

// Safe: provider never returns a usable email at all — the actual upstream
// fix for providers whose API exposes no verified-flag (email trust removed
// entirely rather than gated).
// ok: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function normalize_profile_data_email_removed( $profileData, $provider ) {
	$temp = array();
	if ( $provider == 'exampleprovider' ) {
		$temp['email'] = '';
	}
	return $temp;
}

// === Variant 3: existing-account re-confirmation via unverified attribute equality ===

// Vulnerable: an existing (potentially privileged) account is "confirmed" for
// SSO login by a case-normalized equality check against a resource-owner
// attribute, then logged in — no verified-flag check anywhere in the function.
// ruleid: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function sso_confirm_existing_account_no_verify_check( $user, $idp_email ) {
	if ( in_array( 'administrator', $user->roles, true ) ) {
		$own_email = $user->user_email;
		if ( strtolower( $own_email ) !== strtolower( $idp_email ) ) {
			wp_die( 'Invalid login attempt.' );
		}
	}
	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID );
}

// Vulnerable: positive-equality form of the same confirmation shape.
// ruleid: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function sso_login_if_email_matches_no_verify_check( $user, $idp_email ) {
	if ( in_array( 'administrator', $user->roles, true ) ) {
		$own_email = $user->user_email;
		if ( strtolower( $own_email ) === strtolower( $idp_email ) ) {
			wp_set_current_user( $user->ID );
			wp_set_auth_cookie( $user->ID );
		}
	}
}

// Safe: the resource-owner's own verified-flag is additionally required
// before the equality-matched account may log in (the actual upstream fix
// shape — gate the confirmation on a "verified" attribute from the provider).
// ok: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function sso_confirm_existing_account_with_verify_check( $user, $idp_email, $resource_owner, $verified_key ) {
	if ( in_array( 'administrator', $user->roles, true ) ) {
		$own_email = $user->user_email;
		if ( strtolower( $own_email ) !== strtolower( $idp_email ) ) {
			wp_die( 'Invalid login attempt.' );
		}
		if ( isset( $resource_owner[ $verified_key ] ) && (string) $resource_owner[ $verified_key ] !== '1' ) {
			wp_die( 'Email not verified.' );
		}
	}
	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID );
}

// Safe: a normal WP profile-sync routine — compares the admin's stored email
// to a value for auditing/display purposes only, never calls
// wp_set_auth_cookie()/wp_set_current_user() in this function, so no login
// decision is made from the comparison at all.
// ok: claude.php.wordpress.access-control.oauth-profile-email-verified-flag-ignored
function admin_email_change_notice( $user, $expected_email ) {
	if ( in_array( 'administrator', $user->roles, true ) ) {
		$own_email = $user->user_email;
		if ( strtolower( $own_email ) !== strtolower( $expected_email ) ) {
			update_option( 'mismatch_notice', true );
		}
	}
	return true;
}
