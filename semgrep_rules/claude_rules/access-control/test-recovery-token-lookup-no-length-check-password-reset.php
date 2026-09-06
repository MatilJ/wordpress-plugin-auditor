<?php
// Test cases for claude.php.wordpress.access-control.recovery-token-lookup-no-length-check-password-reset

// ruleid: claude.php.wordpress.access-control.recovery-token-lookup-no-length-check-password-reset
function rest_set_new_password_from_recovery_token() {
	global $wpdb;

	$data = json_decode( file_get_contents( 'php://input' ), true );

	$token    = sanitize_text_field( $data['token'] );
	$password = sanitize_text_field( $data['password'] );

	$table = $wpdb->prefix . 'plugin_recovery_links';
	$sql   = $wpdb->prepare( "SELECT * FROM $table WHERE code = %s", $token );
	$row   = $wpdb->get_row( $sql );

	if ( $row ) {
		$user = get_user_by( 'login', $row->username );
		if ( $user ) {
			wp_set_password( $password, $user->ID );
			return new WP_REST_Response( array( 'success' => true ) );
		}
	}

	return new WP_REST_Response( array( 'success' => false ), 400 );
}

// ruleid: claude.php.wordpress.access-control.recovery-token-lookup-no-length-check-password-reset
function ajax_complete_password_reset() {
	global $wpdb;

	$token = isset( $_REQUEST['reset_code'] ) ? sanitize_text_field( $_REQUEST['reset_code'] ) : '';
	$pass  = isset( $_REQUEST['new_pass'] ) ? sanitize_text_field( $_REQUEST['new_pass'] ) : '';

	$table = $wpdb->prefix . 'plugin_verify_codes';
	$sql   = $wpdb->prepare( "SELECT * FROM $table WHERE reset_code = %s AND used = 0", $token, 0 );
	$row   = $wpdb->get_row( $sql );

	if ( $row && ! empty( $pass ) ) {
		$user = get_user_by( 'login', $row->user_login );
		if ( $user ) {
			wp_set_password( $pass, $user->ID );
			wp_send_json_success();
		}
	}

	wp_send_json_error();
}

// ok: claude.php.wordpress.access-control.recovery-token-lookup-no-length-check-password-reset
function rest_set_new_password_from_recovery_token_fixed( $request ) {
	global $wpdb;

	$data = json_decode( file_get_contents( 'php://input' ), true );

	$token    = sanitize_text_field( $data['token'] ?? '' );
	$password = sanitize_text_field( $data['password'] ?? '' );

	if ( $token === '' || strlen( $token ) < 32 || $password === '' ) {
		return new WP_REST_Response( array( 'success' => false ), 400 );
	}

	$table = $wpdb->prefix . 'plugin_recovery_links';
	$sql   = $wpdb->prepare( "SELECT * FROM $table WHERE code = %s", $token );
	$row   = $wpdb->get_row( $sql );

	if ( $row ) {
		$user = get_user_by( 'login', $row->username );
		if ( $user ) {
			wp_set_password( $password, $user->ID );
			return new WP_REST_Response( array( 'success' => true ) );
		}
	}

	return new WP_REST_Response( array( 'success' => false ), 400 );
}

// ok: claude.php.wordpress.access-control.recovery-token-lookup-no-length-check-password-reset
function core_style_password_reset( $login, $key ) {
	// Standard WP core flow: check_password_reset_key() validates the
	// fixed-length, non-client-influenceable core reset key itself before
	// this ever runs — no bespoke DB equality lookup on request data.
	$user = check_password_reset_key( $key, $login );
	if ( is_wp_error( $user ) ) {
		return $user;
	}

	$password = isset( $_POST['pass1'] ) ? $_POST['pass1'] : '';
	reset_password( $user, $password );
}

// ok: claude.php.wordpress.access-control.recovery-token-lookup-no-length-check-password-reset
function ajax_complete_password_reset_fixed() {
	global $wpdb;

	$token = isset( $_REQUEST['reset_code'] ) ? sanitize_text_field( $_REQUEST['reset_code'] ) : '';
	$pass  = isset( $_REQUEST['new_pass'] ) ? sanitize_text_field( $_REQUEST['new_pass'] ) : '';

	if ( ! preg_match( '/^[a-f0-9]{64}$/i', $token ) ) {
		wp_send_json_error();
		return;
	}

	$table = $wpdb->prefix . 'plugin_verify_codes';
	$sql   = $wpdb->prepare( "SELECT * FROM $table WHERE reset_code = %s AND used = 0", $token, 0 );
	$row   = $wpdb->get_row( $sql );

	if ( $row && ! empty( $pass ) ) {
		$user = get_user_by( 'login', $row->user_login );
		if ( $user ) {
			wp_set_password( $pass, $user->ID );
			wp_send_json_success();
		}
	}

	wp_send_json_error();
}
