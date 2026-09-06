<?php
// Test cases for claude.php.wordpress.access-control.signature-auth-no-replay-guard

class Remote_Dashboard_Proxy {

	private function verify_signature( array $body ): bool {
		$payload   = $body['function'] . '|' . $body['nonce'] . '|' . $body['user'];
		$signature = base64_decode( $body['signature'] );
		$pubkey    = openssl_pkey_get_public( get_option( 'remote_pubkey' ) );
		$result    = openssl_verify( $payload, $signature, $pubkey, OPENSSL_ALGO_SHA256 );
		return 1 === $result;
	}

	public function check_auth_permission( \WP_REST_Request $request ): bool {
		$body = $request->get_json_params();
		if ( is_array( $body ) && $this->verify_signature( $body ) ) {
			$user = get_user_by( 'login', sanitize_user( $body['user'] ?? '' ) );
			if ( ! $user || ! user_can( $user, 'manage_options' ) ) {
				return false;
			}
			// ruleid: claude.php.wordpress.access-control.signature-auth-no-replay-guard
			wp_set_current_user( (int) $user->ID );
			return true;
		}
		return false;
	}
}

class Webhook_HMAC_Login {

	private function verify_webhook( string $body, string $mac_header ): bool {
		$computed = hash_hmac( 'sha256', $body, $this->get_shared_secret() );
		return hash_equals( $computed, $mac_header );
	}

	private function get_shared_secret(): string {
		return (string) get_option( 'webhook_shared_secret' );
	}

	public function handle_webhook( array $data, string $mac_header ): void {
		$raw = wp_json_encode( $data );
		if ( $this->verify_webhook( $raw, $mac_header ) ) {
			$user = get_user_by( 'login', sanitize_user( $data['user'] ?? '' ) );
			if ( $user ) {
				// ruleid: claude.php.wordpress.access-control.signature-auth-no-replay-guard
				wp_set_auth_cookie( $user->ID, false );
			}
		}
	}
}

class Remote_Dashboard_Proxy_Fixed {

	private function consume_nonce( string $nonce, int $issued_at ): bool {
		if ( time() - $issued_at > 300 ) {
			return false;
		}
		return (bool) add_option( 'remote_nonce_' . $nonce, time(), '', false );
	}

	private function verify_signature( array $body ): bool {
		$payload   = $body['function'] . '|' . $body['nonce'] . '|' . $body['user'];
		$signature = base64_decode( $body['signature'] );
		$pubkey    = openssl_pkey_get_public( get_option( 'remote_pubkey' ) );
		$result    = openssl_verify( $payload, $signature, $pubkey, OPENSSL_ALGO_SHA256 );
		if ( 1 !== $result ) {
			return false;
		}
		return $this->consume_nonce( $body['nonce'], (int) $body['nonce_issued_at'] );
	}

	public function check_auth_permission( \WP_REST_Request $request ): bool {
		$body = $request->get_json_params();
		if ( is_array( $body ) && $this->verify_signature( $body ) ) {
			$user = get_user_by( 'login', sanitize_user( $body['user'] ?? '' ) );
			if ( ! $user || ! user_can( $user, 'manage_options' ) ) {
				return false;
			}
			// ok: claude.php.wordpress.access-control.signature-auth-no-replay-guard
			wp_set_current_user( (int) $user->ID );
			return true;
		}
		return false;
	}
}

class Statistics_Report_Reader {

	public function get_report_rows( int $report_id ): array {
		global $wpdb;
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}stats_reports WHERE id = %d",
				$report_id
			)
		);
		return is_array( $rows ) ? $rows : [];
	}

	public function maybe_switch_to_service_account(): void {
		// No signature verification anywhere in this class at all — this is a
		// plain DB-read helper, not a custom auth scheme, so the rule must
		// stay silent here regardless of any session calls elsewhere.
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			// ok: claude.php.wordpress.access-control.signature-auth-no-replay-guard
			wp_set_current_user( 1 );
		}
	}
}
