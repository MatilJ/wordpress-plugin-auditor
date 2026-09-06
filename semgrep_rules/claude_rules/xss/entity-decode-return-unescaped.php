<?php

function parse_imported_review_text( $text ) {
	// ruleid: claude.php.wordpress.xss.entity-decode-return-unescaped
	return preg_replace( '/\r\n|\r|\n/', "\n", trim( html_entity_decode( $text, ENT_HTML5 | ENT_QUOTES ) ) );
}

function render_feed_comment( $raw ) {
	// ruleid: claude.php.wordpress.xss.entity-decode-return-unescaped
	echo html_entity_decode( $raw, ENT_QUOTES );
}

function parse_imported_review_text_fixed( $text ) {
	// ok: claude.php.wordpress.xss.entity-decode-return-unescaped
	return wp_kses_post( preg_replace( '/\r\n|\r|\n/', "\n", trim( html_entity_decode( $text, ENT_HTML5 | ENT_QUOTES ) ) ) );
}

function get_cached_review_text( $wpdb, $id ) {
	// ok: claude.php.wordpress.xss.entity-decode-return-unescaped
	return $wpdb->get_var( $wpdb->prepare( "SELECT review_text FROM wp_reviews WHERE id = %d", $id ) );
}
