<?php

function um_profile_field_filter_hook__textarea( $value, $data ) {
	$value = wp_kses( $value, 'strip' );
	// ruleid: claude.php.wordpress.xss.sanitizer-output-entity-decode-reintroduction
	$value = html_entity_decode( $value );
	return $value;
}

function render_comment_text( $comment ) {
	$clean = strip_tags( $comment );
	// ruleid: claude.php.wordpress.xss.sanitizer-output-entity-decode-reintroduction
	echo html_entity_decode( $clean );
}

function safe_numeric_from_stripped( $input ) {
	$clean = sanitize_text_field( $input );
	$id    = absint( $clean );
	// ok: claude.php.wordpress.xss.sanitizer-output-entity-decode-reintroduction
	return html_entity_decode( $id );
}

function decode_stored_option() {
	$value = get_option( 'my_plugin_setting' );
	// ok: claude.php.wordpress.xss.sanitizer-output-entity-decode-reintroduction
	return html_entity_decode( $value );
}

function render_custom_field_value( $type, $value ) {
	$value = esc_html( $value );
	if ( $type === 'checkboxgroup' || $type === 'radio' ) {
		// ruleid: claude.php.wordpress.xss.sanitizer-output-entity-decode-reintroduction
		$value = html_entity_decode( $value );
	}
	return $value;
}

function render_attr_value( $value ) {
	$safe = esc_attr( $value );
	// ruleid: claude.php.wordpress.xss.sanitizer-output-entity-decode-reintroduction
	echo htmlspecialchars_decode( $safe );
}

function render_escaped_label( $label ) {
	$label = esc_html( $label );
	// ok: claude.php.wordpress.xss.sanitizer-output-entity-decode-reintroduction
	echo $label;
}
