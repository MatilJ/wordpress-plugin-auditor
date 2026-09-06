<?php
// claude.php.wordpress.xss.json-encode-html-comment-breakout test cases
// Pattern rule: json_encode()/wp_json_encode() output reaches a string wrapped
// in literal HTML comment delimiters (<!-- ... -->), either directly or via an
// array-of-parts + implode() indirection — comment-breakout via a literal "-->"
// sequence in the encoded data.
//
// Annotation placement for the array/implode Forms: the pattern-inside anchors
// on the array-push statement, but the reported match is the return/echo
// statement itself. Place the test annotation on the line before the
// return/echo, not before the array-push.

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// Array-of-parts + implode() indirection. Mirrors optimole-wp 4.2.10
// Profile::get_current_profile_html_comment() (inc/v2/PageProfiler/Profile.php:470-489).
class Comment_Breakout_Test {
	public function build_debug_comment( $devices_data ) {
		$comment_parts = [ 'plugin=demo' ];
		foreach ( $devices_data as $device => $data ) {
			$comment_parts[] = 'device-' . $device . '#' . json_encode( $data );
		}
		// ruleid: claude.php.wordpress.xss.json-encode-html-comment-breakout
		return '<!-- ' . implode( ' ', $comment_parts ) . ' -->';
	}

	public function build_debug_comment_wp_json_encode( $devices_data ) {
		$comment_parts = [ 'plugin=demo' ];
		foreach ( $devices_data as $device => $data ) {
			$comment_parts[] = 'device-' . $device . '#' . wp_json_encode( $data );
		}
		// ruleid: claude.php.wordpress.xss.json-encode-html-comment-breakout
		echo '<!-- ' . implode( ' ', $comment_parts ) . ' -->';
	}
}

// Direct inline concatenation, no array/implode indirection.
function build_direct_comment( $data ) {
	// ruleid: claude.php.wordpress.xss.json-encode-html-comment-breakout
	return '<!-- debug: ' . json_encode( $data ) . ' -->';
}

function build_direct_comment_wp_json_encode( $data ) {
	// ruleid: claude.php.wordpress.xss.json-encode-html-comment-breakout
	echo '<!-- debug: ' . wp_json_encode( $data ) . ' -->';
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// esc_html() wraps the implode() result — ">" becomes "&gt;", which breaks the
// literal "-->" match inside a raw-text comment node.
class Comment_Breakout_Safe_Test {
	public function build_debug_comment_escaped( $devices_data ) {
		$comment_parts = [ 'plugin=demo' ];
		foreach ( $devices_data as $device => $data ) {
			$comment_parts[] = 'device-' . $device . '#' . json_encode( $data );
		}
		// ok: claude.php.wordpress.xss.json-encode-html-comment-breakout
		return '<!-- ' . esc_html( implode( ' ', $comment_parts ) ) . ' -->';
	}
}

// esc_html() wraps the direct json_encode() call before comment embedding.
function build_direct_comment_escaped( $data ) {
	// ok: claude.php.wordpress.xss.json-encode-html-comment-breakout
	return '<!-- debug: ' . esc_html( json_encode( $data ) ) . ' -->';
}

// str_replace() strips "--" from the encoded value before comment embedding.
function build_direct_comment_stripped( $data ) {
	// ok: claude.php.wordpress.xss.json-encode-html-comment-breakout
	return '<!-- debug: ' . str_replace( '--', '', json_encode( $data ) ) . ' -->';
}

// JSON_HEX_TAG hex-encodes "<" and ">" to </> — the literal "-->"
// sequence cannot survive in the encoded output.
function build_direct_comment_hex_tag( $data ) {
	// ok: claude.php.wordpress.xss.json-encode-html-comment-breakout
	return '<!-- debug: ' . json_encode( $data, JSON_HEX_TAG ) . ' -->';
}

// json_encode() reaches a <script> block, not an HTML comment — different sink,
// not matched by this rule at all (no <!-- / --> delimiters present).
function build_script_block( $data ) {
	return '<script>var x = ' . json_encode( $data ) . ';</script>';
}

// Array-of-parts implode() with no comment delimiters wrapping the result —
// plain string building, not an HTML comment sink.
class Comment_Breakout_Unrelated_Test {
	public function build_plain_list( $items ) {
		$parts = [];
		foreach ( $items as $item ) {
			$parts[] = 'item#' . json_encode( $item );
		}
		return implode( ', ', $parts );
	}
}
