<?php

class Vulnerable_Sanitizer_Examples {

	public function cleanup_customer_information( $data ) {
		if ( empty( $data['customer_information'] ) || ! is_array( $data['customer_information'] ) ) {
			return $data;
		}

		foreach ( $data['customer_information'] as &$info ) {
			if ( is_string( $info ) ) {
				$info = trim( $info );
				// ruleid: claude.php.wordpress.xss.is-string-only-sanitizer-array-bypass
				$info = sanitize_textarea_field( $info );
			}
		}

		return $data;
	}

	public function sanitize_custom_fields( $fields ) {
		foreach ( $fields as $key => $value ) {
			if ( is_string( $value ) ) {
				// ruleid: claude.php.wordpress.xss.is-string-only-sanitizer-array-bypass
				$fields[ $key ] = esc_html( $value );
			}
		}

		return $fields;
	}

	public function cleanup_customer_information_fixed( $data ) {
		if ( empty( $data['customer_information'] ) || ! is_array( $data['customer_information'] ) ) {
			return $data;
		}

		foreach ( $data['customer_information'] as $key => $value ) {
			if ( is_string( $value ) ) {
				// ok: claude.php.wordpress.xss.is-string-only-sanitizer-array-bypass
				$data['customer_information'][ $key ] = sanitize_textarea_field( $value );
			} elseif ( is_array( $value ) ) {
				$sanitized = array();
				foreach ( $value as $element ) {
					if ( is_string( $element ) ) {
						$sanitized[] = sanitize_text_field( $element );
					}
				}
				$data['customer_information'][ $key ] = $sanitized;
			}
		}

		return $data;
	}

	public function build_display_labels( $rows ) {
		$labels = array();

		foreach ( $rows as $key => $value ) {
			if ( is_string( $value ) ) {
				// ok: claude.php.wordpress.xss.is-string-only-sanitizer-array-bypass
				$labels[ $key ] = get_post_meta( $value, 'label', true );
			}
		}

		return $labels;
	}

	public function store_scheduled_answer( $question_answer ) {
		$answer = '';

		if ( is_array( $question_answer ) && ( $question_answer['date'] != '' || $question_answer['time'] != '' ) ) {
			$question_answer['date'] = $question_answer['date'] != '' ? sanitize_text_field( $question_answer['date'] ) : '-';
			$question_answer['time'] = $question_answer['time'] != '' ? sanitize_text_field( $question_answer['time'] ) : '-';
			$answer = implode( ' ', $question_answer );
		}
		else {
			// ruleid: claude.php.wordpress.xss.is-string-only-sanitizer-array-bypass
			$answer = $question_answer;
		}

		return $answer;
	}

	public function store_scheduled_answer_fixed( $question_answer ) {
		$answer = '';

		if ( is_array( $question_answer ) && ( $question_answer['date'] != '' || $question_answer['time'] != '' ) ) {
			$question_answer['date'] = $question_answer['date'] != '' ? sanitize_text_field( $question_answer['date'] ) : '-';
			$question_answer['time'] = $question_answer['time'] != '' ? sanitize_text_field( $question_answer['time'] ) : '-';
			$answer = implode( ' ', $question_answer );
		}
		else {
			// ok: claude.php.wordpress.xss.is-string-only-sanitizer-array-bypass
			$answer = is_scalar( $question_answer ) ? sanitize_text_field( $question_answer ) : '';
		}

		return $answer;
	}
}
