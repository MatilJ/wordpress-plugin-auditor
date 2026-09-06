<?php

class Form_Input_Sanitizer {

	// named skip-list variable, matches the common real-world shape
	public static function sanitize_recursive( $data, $current_key = '' ) {
		$data = wp_unslash( $data );
		// ruleid: claude.php.wordpress.xss.sanitizer-key-allowlist-bypass
		$skipped_keys = array( 'preview_data' );
		if (
			in_array( $current_key, $skipped_keys, true ) ||
			0 === strpos( $current_key, 'url-' )
		) {
			return $data;
		}

		if ( ! is_array( $data ) ) {
			return sanitize_text_field( $data );
		}
		foreach ( $data as $key => $value ) {
			$data[ $key ] = self::sanitize_recursive( $value, $key );
		}
		return $data;
	}

	// inline array literal form, no intermediate variable
	public static function clean_field_value( $value, $field_key = '' ) {
		// ruleid: claude.php.wordpress.xss.sanitizer-key-allowlist-bypass
		if ( in_array( $field_key, array( 'raw_settings', 'raw_meta' ), true ) ) {
			return $value;
		}
		return wp_kses_post( $value );
	}

	// remediated: the skip condition also constrains the input's shape,
	// so the raw-return path only applies to non-array (JSON string) input
	// ok: claude.php.wordpress.xss.sanitizer-key-allowlist-bypass
	public static function sanitize_recursive_fixed( $data, $current_key = '' ) {
		$data = wp_unslash( $data );
		if ( 'preview_data' === $current_key && ! is_array( $data ) ) {
			return $data;
		}

		if ( ! is_array( $data ) ) {
			return sanitize_text_field( $data );
		}
		foreach ( $data as $key => $value ) {
			$data[ $key ] = self::sanitize_recursive_fixed( $value, $key );
		}
		return $data;
	}

	// no early bypass at all — every key is sanitized before being returned
	// ok: claude.php.wordpress.xss.sanitizer-key-allowlist-bypass
	public static function sanitize_strict( $data, $current_key = '' ) {
		if ( ! is_array( $data ) ) {
			return sanitize_text_field( $data );
		}
		foreach ( $data as $key => $value ) {
			$data[ $key ] = self::sanitize_strict( $value, $key );
		}
		return $data;
	}
}
