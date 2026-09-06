<?php

class Vulnerable_Dynamic_Tag_Handler {

	// Real-world shape: eval() reached only after two reassignment hops
	// through ternary/trim, mirroring the pre-fix w3-total-cache pattern.
	public function _parse_dynamic_mfunc( $matches ) {
		$code1 = trim( $matches[1] );
		$code2 = trim( $matches[2] );
		$code  = ( $code1 ? $code1 : $code2 );

		if ( $code ) {
			$code = trim( $code, ';' ) . ';';
			ob_start();
			// ruleid: claude.php.wordpress.rce.regex-capture-callback-code-execution
			$result = eval( $code );
			$output = ob_get_contents();
			ob_end_clean();
		}

		return $output;
	}

	// Real-world shape: include() of a path built directly from the
	// second capture group, mirroring the pre-fix mclude handler.
	public function _parse_dynamic_mclude( $matches ) {
		$file1 = trim( $matches[1] );
		$file2 = trim( $matches[2] );
		$file  = ( $file1 ? $file1 : $file2 );

		if ( $file ) {
			$file = ABSPATH . $file;
			ob_start();
			// ruleid: claude.php.wordpress.rce.regex-capture-callback-code-execution
			include $file;
			$output = ob_get_contents();
			ob_end_clean();
		}

		return $output;
	}

	// Minimal closure form registered directly as the callback.
	public function register() {
		preg_replace_callback(
			'~<!--tag-->(.*)<!--/tag-->~',
			function ( $match ) {
				// ruleid: claude.php.wordpress.rce.regex-capture-callback-code-execution
				eval( $match[1] );
			},
			$buffer
		);
	}
}

class Fixed_Dynamic_Tag_Handler {

	// 2.10.0-style fix: dispatch to a pre-registered callable by slug,
	// gated by a constant-time HMAC — no eval()/include() of matched text.
	public function _parse_dynamic_mfunc( $matches ) {
		$header = trim( $matches[1] );
		$parsed = $this->parse_header( $header );

		if ( null === $parsed ) {
			return 'refused: missing call:slug + hmac envelope';
		}

		$expected = hash_hmac( 'sha256', $parsed['slug'] . '|' . $parsed['args'], $this->hmac_key() );

		// ok: claude.php.wordpress.rce.regex-capture-callback-code-execution
		if ( ! hash_equals( $expected, $parsed['hmac'] ) ) {
			return 'refused: hmac mismatch';
		}

		return call_user_func( $this->callbacks[ $parsed['slug'] ], $parsed['args'] );
	}

	// Inline hash_equals() guard kept alongside eval() — a plugin that
	// fixes the bug without removing eval() entirely, still safe because
	// the token can no longer be forged from attacker-visible data alone.
	public function _parse_dynamic_mfunc_alt( $matches ) {
		$token = trim( $matches[1] );

		if ( ! hash_equals( $this->server_secret(), $token ) ) {
			return 'refused';
		}

		// ok: claude.php.wordpress.rce.regex-capture-callback-code-execution
		return eval( trim( $matches[2] ) );
	}

	// Common, overwhelmingly-legitimate preg_replace_callback usage: builds
	// a safe string from the capture, never reaches eval()/include() at all.
	public function highlight_code( $matches ) {
		// ok: claude.php.wordpress.rce.regex-capture-callback-code-execution
		return '<code>' . esc_html( $matches[1] ) . '</code>';
	}

	// Numeric-only capture cannot form executable PHP or a traversable path.
	public function resolve_page_number( $matches ) {
		$page = absint( $matches[1] );
		// ok: claude.php.wordpress.rce.regex-capture-callback-code-execution
		eval( "\$n = $page;" );
	}

	// Path built from the capture but resolved through realpath() first —
	// standard traversal-safe include gate.
	public function include_partial( $matches ) {
		$path = realpath( PLUGIN_DIR . '/partials/' . $matches[1] . '.php' );
		// ok: claude.php.wordpress.rce.regex-capture-callback-code-execution
		include $path;
	}
}
