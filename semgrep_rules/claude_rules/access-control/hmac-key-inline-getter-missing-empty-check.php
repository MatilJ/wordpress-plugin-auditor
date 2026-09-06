<?php

class WebhookVerifier {
	public function verifySignature() {
		// ruleid: claude.php.wordpress.access-control.hmac-key-inline-getter-missing-empty-check
		return hash_hmac( 'sha256', $this->getPayload(), $this->getSigningSecret() );
	}
}

class TokenSigner {
	public function sign( $data ) {
		// ruleid: claude.php.wordpress.access-control.hmac-key-inline-getter-missing-empty-check
		return hash_hmac( 'sha256', $data, Settings::getApiSecret() );
	}
}

class WebhookVerifierFixed {
	public function verifySignature() {
		$secret = $this->getSigningSecret();
		if ( ! is_string( $secret ) || '' === $secret ) {
			return false;
		}
		// ok: claude.php.wordpress.access-control.hmac-key-inline-getter-missing-empty-check
		return hash_equals( hash_hmac( 'sha256', $this->getPayload(), $secret ), $this->getSignature() );
	}
}

class AutoLoginToken {
	public function computeToken( $user_id ) {
		// ok: claude.php.wordpress.access-control.hmac-key-inline-getter-missing-empty-check
		return hash_hmac( 'sha256', (string) $user_id, wp_salt( 'auth' ) );
	}
}
