<?php

function check_nonce_vulnerable() {
	if ( isset( $_POST['el-action'] ) ) {
		$action = sanitize_text_field( $_POST['el-action'] );

		if ( ! isset( $_POST[ $action . '_nonce' ] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST[ $action . '_nonce' ], $action ) ) {
			return;
		}
	}

	do_action( 'el_action', $action, $_REQUEST );
	// ruleid: claude.php.wordpress.rce.dynamic-hook-name-do-action
	do_action( $action, $_REQUEST );
}

function apply_filters_hook_injection() {
	$hook = sanitize_key( $_GET['hook'] );
	// ruleid: claude.php.wordpress.rce.dynamic-hook-name-do-action
	$result = apply_filters( $hook, $_GET['value'] );
	return $result;
}

function ref_array_hook_injection() {
	$action = wp_unslash( $_REQUEST['action'] );
	// ruleid: claude.php.wordpress.rce.dynamic-hook-name-do-action
	do_action_ref_array( $action, array( $_REQUEST ) );
}

function check_nonce_fixed() {
	$allowed_actions = array(
		'el-download-system-info',
		'el_license_activate',
	);

	if ( isset( $_POST['el-action'] ) ) {
		$action = sanitize_text_field( $_POST['el-action'] );

		if ( ! in_array( $action, $allowed_actions ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST[ $action . '_nonce' ], $action ) ) {
			return;
		}
	}

	do_action( 'el_action', $action, $_REQUEST );
	// ok: claude.php.wordpress.rce.dynamic-hook-name-do-action
	do_action( $action, $_REQUEST );
}

function static_hook_name_is_safe() {
	// ok: claude.php.wordpress.rce.dynamic-hook-name-do-action
	do_action( 'my_plugin_loaded', get_option( 'my_plugin_settings' ) );
	// ok: claude.php.wordpress.rce.dynamic-hook-name-do-action
	apply_filters( 'my_plugin_content', get_post_field( 'post_content', get_the_ID() ) );
}

// Same self-referential-nonce shape as check_nonce_vulnerable() above, but
// with no allow-list at all -- the sibling plugin's variant of this bug.
function check_nonce_no_allowlist() {
	if ( isset( $_POST['check-email-action'] ) ) {
		$action = sanitize_text_field( wp_unslash( $_POST['check-email-action'] ) );

		if ( ! isset( $_POST[ $action . '_nonce' ] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST[ $action . '_nonce' ], $action ) ) {
			return;
		}
	}

	do_action( 'check_email_action', $action, $_REQUEST );
	// ruleid: claude.php.wordpress.rce.dynamic-hook-name-do-action
	do_action( $action, $_REQUEST );
}

// Fix idiom: a current_user_can() gate (not an allow-list) protects the
// dispatcher before the tainted hook name reaches do_action().
function check_nonce_fixed_with_capability_check() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return false;
	}

	if ( isset( $_POST['check-email-action'] ) ) {
		$action = sanitize_text_field( wp_unslash( $_POST['check-email-action'] ) );

		if ( ! isset( $_POST[ $action . '_nonce' ] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST[ $action . '_nonce' ], $action ) ) {
			return;
		}
	}

	do_action( 'check_email_action', $action, $_REQUEST );
	// ok: claude.php.wordpress.rce.dynamic-hook-name-do-action
	do_action( $action, $_REQUEST );
}

// Same fix idiom, gated by is_user_logged_in() instead.
function dispatch_logged_in_only() {
	if ( ! is_user_logged_in() ) {
		return;
	}

	$hook = sanitize_text_field( wp_unslash( $_REQUEST['action'] ) );
	// ok: claude.php.wordpress.rce.dynamic-hook-name-do-action
	do_action( $hook, $_REQUEST );
}
