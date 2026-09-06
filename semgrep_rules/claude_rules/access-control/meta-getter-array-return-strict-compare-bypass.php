<?php

// ruleid: claude.php.wordpress.access-control.meta-getter-array-return-strict-compare-bypass
function clear_user_session_example() {
	$user_info = $_POST['user_info'];
	try {
		$token = get_user_meta( $user_info['user_id'], 'session_token' );
		if ( ! wp_verify_nonce( $user_info['_wpnonce'], 'clear_sessions' ) && $token !== $user_info['session_token'] ) {
			throw new \Exception( 'Invalid nonce.' );
		}
		$sessions = WP_Session_Tokens::get_instance( $user_info['user_id'] );
		$sessions->destroy_all();
	} catch ( \Exception $e ) {
		wp_send_json_error( array( 'message' => $e->getMessage() ) );
	}
}

// ruleid: claude.php.wordpress.access-control.meta-getter-array-return-strict-compare-bypass
function verify_post_api_key( $request ) {
	$post_id        = absint( $request['post_id'] );
	$submitted_key  = sanitize_text_field( $request['api_key'] );
	$stored_key     = get_post_meta( $post_id, '_api_key' );
	if ( $submitted_key === $stored_key ) {
		return true;
	}
	return new WP_Error( 'invalid_key', 'Invalid API key' );
}

function clear_user_session_fixed() {
	$user_info = $_POST['user_info'];
	try {
		$user_id = absint( $user_info['user_id'] );
		if ( ! wp_verify_nonce( $user_info['_wpnonce'], 'clear_sessions' ) ) {
			throw new \Exception( 'Invalid nonce.' );
		}
		$stored_token   = (string) get_user_meta( $user_id, 'session_token', true );
		$supplied_token = (string) $user_info['session_token'];
		// ok: claude.php.wordpress.access-control.meta-getter-array-return-strict-compare-bypass
		if ( empty( $stored_token ) || ! hash_equals( $stored_token, $supplied_token ) ) {
			throw new \Exception( 'Invalid session token.' );
		}
		$sessions = WP_Session_Tokens::get_instance( $user_id );
		$sessions->destroy_all();
	} catch ( \Exception $e ) {
		wp_send_json_error( array( 'message' => $e->getMessage() ) );
	}
}

function verify_api_key_fixed( $post_id, $submitted_key ) {
	$stored_key = get_post_meta( $post_id, '_api_key', true );
	// ok: claude.php.wordpress.access-control.meta-getter-array-return-strict-compare-bypass
	if ( $submitted_key === $stored_key ) {
		return true;
	}
	return false;
}
