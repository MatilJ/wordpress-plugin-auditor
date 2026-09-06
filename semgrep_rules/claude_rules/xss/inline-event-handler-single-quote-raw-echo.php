<?php
// Test cases for claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo

function column_status( $item ) {
	// ruleid: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$toggle_url = add_query_arg(
		[
			'action' => 'toggle_active',
			'nonce'  => wp_create_nonce( 'archive_thing' ),
			'id'     => $item->id,
		]
	);
	?>
	<sc-switch checked="<?php echo esc_attr( $item->enabled ) ? 'true' : 'false'; ?>"
		onClick="window.location.assign('<?php echo esc_url_raw( $toggle_url ); ?>'); document.querySelector('#loading').style.display = '';"></sc-switch>
	<?php
}

function render_row( $row ) {
	// ruleid: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$dismiss_url = remove_query_arg( 'notice' );
	?>
	<a onchange="location.href='<?php echo $dismiss_url; ?>';">Dismiss</a>
	<?php
}

function column_status_fixed( $item ) {
	// ok: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$toggle_url = add_query_arg(
		[
			'action' => 'toggle_active',
			'nonce'  => wp_create_nonce( 'archive_thing' ),
			'id'     => $item->id,
		],
		admin_url( 'admin.php?page=my-plugin' )
	);
	?>
	<sc-switch checked="<?php echo esc_attr( $item->enabled ) ? 'true' : 'false'; ?>"
		onClick="window.location.assign('<?php echo esc_url( $toggle_url ); ?>'); document.querySelector('#loading').style.display = '';"></sc-switch>
	<?php
}

function render_row_escaped( $row ) {
	// ok: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$dismiss_url = remove_query_arg( 'notice' );
	?>
	<a onchange="location.href='<?php echo esc_js( $dismiss_url ); ?>';">Dismiss</a>
	<?php
}

function render_action_button( $resource_id ) {
	global $wpdb;
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$active_locale = isset( $_REQUEST['ui_locale'] ) ? sanitize_text_field( $_REQUEST['ui_locale'] ) : 'en_US';

	$html = '';
	// ruleid: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$html .= '<button type="button" onclick="submitForm(this.form,' . $resource_id . ',\'' . $active_locale . '\');" >Send</button>';

	return $html;
}

function render_cancel_button( $booking_hash, $resource_id ) {
	$locale = get_current_ui_locale();

	$html = '';
	// ruleid: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$html .= '<input type="button" value="Cancel" onclick="cancelBooking(\'' . $booking_hash . '\',' . $resource_id . ', \'' . $locale . '\' );" />';

	return $html;
}

function render_action_button_fixed( $resource_id ) {
	global $wpdb;
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$active_locale = isset( $_REQUEST['ui_locale'] ) ? sanitize_text_field( $_REQUEST['ui_locale'] ) : 'en_US';

	$html = '';
	// ok: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$html .= '<button type="button" onclick="submitForm(this.form,' . (int) $resource_id . ',\'' . esc_js( $active_locale ) . '\');" >Send</button>';

	return $html;
}

function render_readonly_row( $post_id ) {
	$row_id = (int) $post_id;

	$html = '';
	// ok: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	$html .= '<tr onclick="location.href=\'' . esc_js( get_permalink( $row_id ) ) . '\';">Row</tr>';

	return $html;
}

function build_panel_click_script( $tab_id, $panel_id ) {
	// ok: claude.php.wordpress.xss.inline-event-handler-single-quote-raw-echo
	// A local variable literally named $onclick (not an HTML attribute) must
	// not be mistaken for an onclick="..." sink.
	$onclick = "javascript:panel_click( '#" . $tab_id . " a' ,'#" . $panel_id . "' );";

	return $onclick;
}
