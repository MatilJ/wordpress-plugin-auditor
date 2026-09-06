<?php
// Test cases for claude.php.wordpress.access-control.password-reset-recipient-no-email-ownership-check

// ruleid: claude.php.wordpress.access-control.password-reset-recipient-no-email-ownership-check
function handle_forgot_password_vulnerable( $request ) {
	$form_data = $request->get_body_params();

	$email    = isset( $form_data['email'] ) ? sanitize_email( $form_data['email'] ) : '';
	$username = isset( $form_data['username'] ) ? sanitize_text_field( $form_data['username'] ) : '';

	$user = get_user_by( 'login', $username );
	if ( ! $user ) {
		return new WP_REST_Response( array( 'message' => 'User not found' ), 404 );
	}

	$key = get_password_reset_key( $user );

	$body = 'Reset link: ' . $key;
	$sent = wp_mail( $email, 'Password reset', $body );

	return new WP_REST_Response( array( 'sent' => $sent ), 200 );
}

// ruleid: claude.php.wordpress.access-control.password-reset-recipient-no-email-ownership-check
function ajax_reset_by_id() {
	$target_id = isset( $_REQUEST['user_id'] ) ? (int) $_REQUEST['user_id'] : 0;
	$recipient = isset( $_REQUEST['recipient'] ) ? sanitize_email( $_REQUEST['recipient'] ) : '';

	$user = get_user_by( 'id', $target_id );
	if ( ! $user ) {
		wp_send_json_error( 'User not found' );
	}

	$key = get_password_reset_key( $user );

	mail( $recipient, 'Reset your password', "Key: $key" );
	wp_send_json_success();
}

// ok: claude.php.wordpress.access-control.password-reset-recipient-no-email-ownership-check
function handle_forgot_password_fixed( $request ) {
	$form_data = $request->get_body_params();

	$email    = isset( $form_data['email'] ) ? sanitize_email( $form_data['email'] ) : '';
	$username = isset( $form_data['username'] ) ? sanitize_text_field( $form_data['username'] ) : '';

	$user = get_user_by( 'login', $username );
	if ( ! $user ) {
		return new WP_REST_Response( array( 'message' => 'User not found' ), 404 );
	}

	$user_email = $user->get( 'user_email' );
	if ( $email !== $user_email ) {
		return new WP_REST_Response( array( 'message' => 'Invalid email address' ), 404 );
	}
	$email = $user_email;

	$key = get_password_reset_key( $user );

	$body = 'Reset link: ' . $key;
	$sent = wp_mail( $email, 'Password reset', $body );

	return new WP_REST_Response( array( 'sent' => $sent ), 200 );
}

// ok: claude.php.wordpress.access-control.password-reset-recipient-no-email-ownership-check
function core_style_retrieve_password( $login ) {
	$user_data = get_user_by( 'login', $login );
	if ( ! $user_data ) {
		return;
	}

	$key = get_password_reset_key( $user_data );

	wp_mail( $user_data->user_email, 'Password reset', "Key: $key" );
}

// ok: claude.php.wordpress.access-control.password-reset-recipient-no-email-ownership-check
function reset_by_email_only( $request ) {
	$form_data = $request->get_body_params();
	$email     = isset( $form_data['email'] ) ? sanitize_email( $form_data['email'] ) : '';

	// The identifier that resolved the account IS the same value later used
	// as the recipient — no independent, attacker-controlled second field.
	$user = get_user_by( 'email', $email );
	if ( ! $user ) {
		return;
	}

	$key = get_password_reset_key( $user );

	wp_mail( $email, 'Password reset', "Key: $key" );
}
