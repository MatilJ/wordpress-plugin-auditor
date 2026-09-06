<?php

class Keyed_Field_Value_Test {

	public function build_card_data_two_step( $user_id, $fields ) {
		$data = array();
		foreach ( $fields as $key ) {
			if ( ! $key ) {
				continue;
			}
			$value = get_user_meta( $user_id, $key, true );
			if ( ! $value ) {
				continue;
			}
			// ruleid: claude.php.wordpress.xss.keyed-field-value-unescaped-array-write
			$data[ $key ] = $value;
		}
		return $data;
	}

	public function build_card_data_one_step( $user_id, $fields ) {
		$data = array();
		foreach ( $fields as $key ) {
			// ruleid: claude.php.wordpress.xss.keyed-field-value-unescaped-array-write
			$data[ $key ] = get_user_meta( $user_id, $key, true );
		}
		return $data;
	}

	public function build_card_data_escaped( $user_id, $fields ) {
		$data = array();
		foreach ( $fields as $key ) {
			$value = get_user_meta( $user_id, $key, true );
			if ( ! $value ) {
				continue;
			}
			// ok: claude.php.wordpress.xss.keyed-field-value-unescaped-array-write
			$data[ $key ] = wp_kses( $value, array() );
		}
		return $data;
	}

	public function build_card_data_esc_html( $user_id, $fields ) {
		$data = array();
		foreach ( $fields as $key ) {
			// ok: claude.php.wordpress.xss.keyed-field-value-unescaped-array-write
			$data[ $key ] = esc_html( get_user_meta( $user_id, $key, true ) );
		}
		return $data;
	}

	public function unrelated_literal_key_assignment( $user_id ) {
		global $wpdb;
		$data = array();
		$data['id'] = $user_id;
		// ok: claude.php.wordpress.xss.keyed-field-value-unescaped-array-write
		$data['role'] = $wpdb->get_var( "SELECT role FROM {$wpdb->prefix}users WHERE ID = " . (int) $user_id );
		return $data;
	}

	public function dedupe_existing_array_values( $devices, $selectors ) {
		$css_selectors = array();
		foreach ( $devices as $device ) {
			$css_selectors[ $device ] = array();
			foreach ( $selectors as $selector ) {
				$css_selectors[ $device ][] = $selector;
			}
			// ok: claude.php.wordpress.xss.keyed-field-value-unescaped-array-write
			$css_selectors[ $device ] = array_unique( $css_selectors[ $device ] );
		}
		return $css_selectors;
	}

	public function merge_existing_urls_per_device( $devices, $lcp_data ) {
		$preload_urls = array();
		foreach ( $devices as $device ) {
			$preload_urls[ $device ] = array();
			if ( ! empty( $lcp_data[ $device ]['bgUrls'] ) ) {
				// ok: claude.php.wordpress.xss.keyed-field-value-unescaped-array-write
				$preload_urls[ $device ] = array_merge( $preload_urls[ $device ], $lcp_data[ $device ]['bgUrls'] );
			}
		}
		return $preload_urls;
	}
}
