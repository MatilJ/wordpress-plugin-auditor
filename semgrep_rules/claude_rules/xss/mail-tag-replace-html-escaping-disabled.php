<?php
// Test cases for mail-tag-replace-html-escaping-disabled

// ---- VULNERABLE: the real pre-fix shape — wrapper call with an empty
// options array (HTML-escaping left at its false default) ----

class FireScript_Action_Test {
	public function process( $submission ) {
		$script = $this->get( 'script' );
		// ruleid: claude.php.wordpress.xss.mail-tag-replace-html-escaping-disabled
		$script = $this->replace_tags( $script, array() );
		return $script;
	}
}

// ---- VULNERABLE: wrapper call with no options argument at all — the
// default ('') also resolves to HTML-escaping disabled ----

class Webhook_Action_Test {
	public function build_payload( $template ) {
		// ruleid: claude.php.wordpress.xss.mail-tag-replace-html-escaping-disabled
		$payload = $this->replace_tags( $template );
		return $payload;
	}
}

// ---- VULNERABLE: the shared Contact Form 7 core function called directly,
// with an options array present but not enabling 'html' => true ----

function build_snippet_test( $template ) {
	// ruleid: claude.php.wordpress.xss.mail-tag-replace-html-escaping-disabled
	$snippet = wpcf7_mail_replace_tags( $template, array( 'exclude_blank' => true ) );
	return $snippet;
}

// ---- SAFE: the actual fix — pass `true` so the wrapper enables
// 'html' => true internally before returning ----

class FireScript_Action_Fixed_Test {
	public function process( $submission ) {
		$script = $this->get( 'script' );
		// ok: claude.php.wordpress.xss.mail-tag-replace-html-escaping-disabled
		$script = $this->replace_tags( $script, true );
		return $script;
	}
}

// ---- SAFE: explicit options array enabling 'html' => true on the direct
// core-function call ----

function build_snippet_fixed_test( $template ) {
	// ok: claude.php.wordpress.xss.mail-tag-replace-html-escaping-disabled
	$snippet = wpcf7_mail_replace_tags( $template, array( 'html' => true ) );
	return $snippet;
}

// ---- SAFE: ordinary WP DB read, unrelated to mail-tag replacement — must
// not be flagged ----

function get_rows_test() {
	global $wpdb;
	// ok: claude.php.wordpress.xss.mail-tag-replace-html-escaping-disabled
	$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}my_table" );
	return $rows;
}
