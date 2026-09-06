<?php

class Webhook_Endpoint_A {
	public function webhook_permission_check( $request ) {
		$signature = $request->get_header( 'x-webhook-signature' );

		if ( empty( $signature ) ) {
			$allowed_ips = apply_filters( 'my_webhook_allowed_ips', array() );

			if ( ! empty( $allowed_ips ) ) {
				$remote_ip = $_SERVER['REMOTE_ADDR'];

				if ( ! in_array( $remote_ip, $allowed_ips, true ) ) {
					return new WP_Error( 'unauthorized', 'Unauthorized.', array( 'status' => 403 ) );
				}
			}
		}

		if ( ! empty( $signature ) ) {
			$secret_key = get_option( 'my_webhook_secret' );

			$calculated_signature = hash_hmac( 'sha256', $request->get_body(), $secret_key );

			if ( ! hash_equals( $calculated_signature, $signature ) ) {
				return new WP_Error( 'invalid_signature', 'Invalid signature.', array( 'status' => 403 ) );
			}
		}

		// ruleid: claude.php.wordpress.access-control.rest-permission-callback-optional-verify-default-allow
		return true;
	}
}

class Payment_Gateway_Callback {
	public function verify_payment_notification( $request ) {
		$token = $request->get_header( 'x-api-token' );

		if ( ! empty( $token ) ) {
			$stored_token = get_option( 'payment_gateway_token' );

			if ( $token !== $stored_token ) {
				return false;
			}
		}

		// ruleid: claude.php.wordpress.access-control.rest-permission-callback-optional-verify-default-allow
		return true;
	}
}

class Webhook_Endpoint_Fixed {
	public function webhook_permission_check( $request ) {
		$signature = $request->get_header( 'x-webhook-signature' );

		if ( empty( $signature ) ) {
			return new WP_Error( 'unauthorized', 'Missing signature header.', array( 'status' => 403 ) );
		}

		$secret_key = get_option( 'my_webhook_secret' );

		$calculated_signature = hash_hmac( 'sha256', $request->get_body(), $secret_key );

		if ( ! hash_equals( $calculated_signature, $signature ) ) {
			return new WP_Error( 'invalid_signature', 'Invalid signature.', array( 'status' => 403 ) );
		}

		// ok: claude.php.wordpress.access-control.rest-permission-callback-optional-verify-default-allow
		return true;
	}
}

class Standard_Capability_Permission {
	public function permission_check( $request ) {
		$token = $request->get_header( 'x-debug-token' );

		if ( ! empty( $token ) ) {
			my_debug_log( $token );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
		}

		// ok: claude.php.wordpress.access-control.rest-permission-callback-optional-verify-default-allow
		return true;
	}
}
