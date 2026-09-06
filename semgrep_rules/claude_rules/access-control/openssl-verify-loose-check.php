<?php

function validate_license_signature( $data, $signature, $public_key ) {
	// ruleid: claude.php.wordpress.access-control.openssl-verify-loose-check
	if ( ! openssl_verify( $data, $signature, $public_key, OPENSSL_ALGO_SHA256 ) ) {
		throw new Exception( 'Invalid signature' );
	}
	return true;
}

function check_webhook_signature( $payload, $signature, $public_key ) {
	// ruleid: claude.php.wordpress.access-control.openssl-verify-loose-check
	$result = openssl_verify( $payload, $signature, $public_key, OPENSSL_ALGO_SHA256 );
	if ( ! $result ) {
		return false;
	}
	return true;
}

function check_response_signature( $payload, $signature, $public_key ) {
	// ruleid: claude.php.wordpress.access-control.openssl-verify-loose-check
	$result = openssl_verify( $payload, $signature, $public_key, OPENSSL_ALGO_SHA256 );
	if ( $result == 0 ) {
		return false;
	}
	return true;
}

class Assertion_Validator {
	public static function validate_signature( array $info, $key ) {
		$obj_xml_sec_dsig = $info['Signature'];
		// ruleid: claude.php.wordpress.access-control.openssl-verify-loose-check
		if ( ! $obj_xml_sec_dsig->verify( $key ) ) {
			throw new Exception( 'Unable to validate Signature' );
		}
	}
}

function validate_license_signature_fixed( $data, $signature, $public_key ) {
	// ok: claude.php.wordpress.access-control.openssl-verify-loose-check
	$result = openssl_verify( $data, $signature, $public_key, OPENSSL_ALGO_SHA256 );
	if ( 1 !== $result ) {
		throw new Exception( 'Invalid signature' );
	}
	return true;
}

function check_webhook_signature_fixed( $payload, $signature, $public_key ) {
	// ok: claude.php.wordpress.access-control.openssl-verify-loose-check
	$result = openssl_verify( $payload, $signature, $public_key, OPENSSL_ALGO_SHA256 );
	if ( 1 === $result ) {
		return true;
	}
	return false;
}

class Assertion_Validator_Fixed {
	public static function validate_signature( array $info, $key ) {
		$obj_xml_sec_dsig = $info['Signature'];
		// ok: claude.php.wordpress.access-control.openssl-verify-loose-check
		if ( 1 !== $obj_xml_sec_dsig->verify( $key ) ) {
			throw new Exception( 'Unable to validate Signature' );
		}
	}
}

function get_user_from_db( $user_id ) {
	global $wpdb;
	// ok: claude.php.wordpress.access-control.openssl-verify-loose-check
	return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE id = %d', $wpdb->users, $user_id ) );
}
