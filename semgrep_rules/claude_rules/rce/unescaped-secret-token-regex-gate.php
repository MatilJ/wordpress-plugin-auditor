<?php

class Vulnerable_Dynamic_Tag_Gate {

	// Real-world shape: a site-wide secret constant is concatenated raw into
	// the mfunc-tag pattern, gating a preg_replace_callback() whose captured
	// group is later eval()'d by the registered callback.
	public function _parse_dynamic( $buffer ) {
		if ( ! defined( 'PLUGIN_DYNAMIC_SECURITY' ) || empty( PLUGIN_DYNAMIC_SECURITY ) ) {
			return $buffer;
		}

		// ruleid: claude.php.wordpress.rce.unescaped-secret-token-regex-gate
		$buffer = preg_replace_callback(
			'~<!--\s*mfunc\s*' . PLUGIN_DYNAMIC_SECURITY . '(.*)-->(.*)<!--\s*/mfunc\s*' . PLUGIN_DYNAMIC_SECURITY . '\s*-->~Uis',
			array( $this, '_parse_dynamic_mfunc' ),
			$buffer
		);

		return $buffer;
	}

	public function _parse_dynamic_mfunc( $matches ) {
		$code = trim( $matches[1] );
		return $code ? eval( $code . ';' ) : '';
	}

	// Variant: preg_match() gate (not preg_replace_callback()) built from a
	// differently-named shared-secret constant, same missing preg_quote().
	public function has_signed_tag( $buffer ) {
		// ruleid: claude.php.wordpress.rce.unescaped-secret-token-regex-gate
		return preg_match( '~<!--\s*mclude\s*' . MCLUDE_SECURITY_TOKEN . '(.*)-->~Uis', $buffer );
	}
}

class Fixed_Dynamic_Tag_Gate {

	// 2.9.2-style fix: the secret is escaped through preg_quote() before
	// being interpolated into the pattern, so metacharacters in its value
	// are matched literally rather than interpreted as regex syntax.
	public function _parse_dynamic( $buffer ) {
		if ( ! defined( 'PLUGIN_DYNAMIC_SECURITY' ) || empty( PLUGIN_DYNAMIC_SECURITY ) ) {
			return $buffer;
		}

		$security = preg_quote( PLUGIN_DYNAMIC_SECURITY, '~' );

		// ok: claude.php.wordpress.rce.unescaped-secret-token-regex-gate
		$buffer = preg_replace_callback(
			'~<!--\s*mfunc\s+' . $security . '(.*)-->(.*)<!--\s*/mfunc\s+' . $security . '\s*-->~Uis',
			array( $this, '_parse_dynamic_mfunc' ),
			$buffer
		);

		return $buffer;
	}

	public function _parse_dynamic_mfunc( $matches ) {
		$code = trim( $matches[1] );
		return $code ? eval( $code . ';' ) : '';
	}

	// Common, unrelated preg_replace_callback() usage: the pattern is built
	// from a non-secret option value (a stored date/number format string),
	// so the secret-named source never appears — nothing to sanitize.
	public function format_dates( $buffer ) {
		$date_format = get_option( 'date_format' );
		// ok: claude.php.wordpress.rce.unescaped-secret-token-regex-gate
		return preg_replace_callback(
			'~\{date:' . $date_format . '\}~',
			function ( $matches ) {
				return date( $matches[1] );
			},
			$buffer
		);
	}
}
