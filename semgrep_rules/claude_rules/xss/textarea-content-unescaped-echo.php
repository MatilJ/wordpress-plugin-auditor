<?php

// Test cases for claude.php.wordpress.xss.textarea-content-unescaped-echo

// --- TRUE POSITIVES ---

function render_entry_memo_tp1( $entry_setting ) {
	// ruleid: claude.php.wordpress.xss.textarea-content-unescaped-echo
	?><td><textarea name="entry[memo]" cols="50" rows="5"><?php echo $entry_setting->get( 'memo' ); ?></textarea></td><?php
}

function render_ticket_notes_tp2( $ticket ) {
	// ruleid: claude.php.wordpress.xss.textarea-content-unescaped-echo
	?><textarea id="internal_notes" rows="4"><?php echo $ticket['notes']; ?></textarea><?php
}

function render_entry_memo_tp3_attr_on_same_line( $entry_setting ) {
	// A sibling esc_attr() call escapes the tag's own name="" attribute on
	// the SAME line — the textarea's inner content is still unescaped and
	// must still be flagged (this is the exact real-world shape).
	// ruleid: claude.php.wordpress.xss.textarea-content-unescaped-echo
	?><td><textarea name="<?php echo esc_attr( 'entry' ); ?>[memo]" cols="50" rows="5"><?php echo $entry_setting->get( 'memo' ); ?></textarea></td><?php
}

function render_comment_body_tp4_short_echo( $comment ) {
	// ruleid: claude.php.wordpress.xss.textarea-content-unescaped-echo
	?><textarea class="comment-edit"><?= $comment->body; ?></textarea><?php
}

// --- FALSE POSITIVES (properly escaped, or not this sink at all) ---

function render_entry_memo_fixed( $entry_setting ) {
	// ok: claude.php.wordpress.xss.textarea-content-unescaped-echo
	?><td><textarea name="entry[memo]" cols="50" rows="5"><?php echo esc_textarea( $entry_setting->get( 'memo' ) ); ?></textarea></td><?php
}

function render_ticket_notes_fixed( $ticket ) {
	// ok: claude.php.wordpress.xss.textarea-content-unescaped-echo
	?><textarea id="internal_notes" rows="4"><?php echo esc_html( $ticket['notes'] ); ?></textarea><?php
}

function render_wpdb_row_not_a_textarea( $wpdb ) {
	// A raw $wpdb result echoed unescaped, but into a <div>, not a
	// <textarea> — out of scope for this sink-specific rule.
	// ok: claude.php.wordpress.xss.textarea-content-unescaped-echo
	$row = $wpdb->get_row( "SELECT note FROM {$wpdb->prefix}my_table WHERE id = 1" );
	echo '<div class="note">' . $row->note . '</div>';
}
