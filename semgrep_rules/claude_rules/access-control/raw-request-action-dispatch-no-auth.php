<?php

// Test cases for claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth

class MyPlugin {

	// TP: raw $_POST["action"] string match dispatches directly to a method call,
	// no isPluginActive() gate and no nonce/capability check anywhere nearby —
	// canonical vulnerable pattern (third-party-plugin compat shim).
	public function __construct() {
		// ruleid: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
		if ( $_POST["action"] == "yasr_send_visitor_rating" ) {
			if ( isset( $_POST["post_id"] ) ) {
				$this->purgeCache( $_POST["post_id"] );
			}
		}
	}

	// TP: raw $_REQUEST["task"] match directly registers a hook callback.
	public function maybe_register() {
		// ruleid: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
		if ( $_REQUEST["task"] == "third_party_sync" ) {
			add_action( 'init', array( $this, "syncNow" ) );
		}
	}

	// ok: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
	// Normal AJAX dispatch through the wp_ajax_ hook system with a nonce check
	// inside the registered callback, not a raw superglobal comparison gate.
	public function ajax_init() {
		add_action( 'wp_ajax_my_plugin_action', array( $this, 'handle_ajax' ) );
	}

	public function handle_ajax() {
		check_ajax_referer( 'my_plugin_nonce' );
		$this->purgeCache( $_POST["post_id"] );
	}

	// ok: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
	// Key is not an action-style parameter name, so it falls outside this rule's scope.
	public function render() {
		if ( $_POST["template"] == "grid" ) {
			$this->renderGrid();
		}
	}

	public function purgeCache( $post_id ) {}
	public function syncNow() {}
	public function renderGrid() {}

	// TP: callback already registered on an ambient hook (all_admin_notices fires
	// on every /wp-admin/ page) reads $_REQUEST["action"] and calls a direct WP
	// Core state-mutating function with no nonce check anywhere in the function —
	// the exact UpdraftPlus 1.26.5 admin.php:3509 restore-abort CSRF shape.
	public function show_admin_notice() {
		// ruleid: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
		if ( isset( $_REQUEST['action'] ) && 'my_plugin_abort' === $_REQUEST['action'] && ! empty( $_REQUEST['job_id'] ) ) {
			delete_site_option( 'my_plugin_job_in_progress' );
			return;
		}
	}

	// TP: same shape via update_option() instead of delete_site_option().
	public function handle_dismiss() {
		// ruleid: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
		if ( $_REQUEST["action"] == "dismiss_notice" ) {
			update_option( 'my_plugin_notice_dismissed', true );
		}
	}

	// TP (by this rule's design): same action-style key and direct-call shape as
	// show_admin_notice() above; a nonce check happens to gate this branch, but
	// the rule cannot see that without deeper analysis (same limitation as the
	// existing $OBJ->$METHOD/add_action arms above, which also don't exclude
	// nonce-gated instances) — this is a LOW-confidence lead by design, not a
	// guaranteed vulnerability; the TRIAGE note directs the reader to check for
	// exactly this.
	public function handle_abort_with_nonce() {
		// ruleid: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
		if ( isset( $_REQUEST['action'] ) && 'my_plugin_abort' === $_REQUEST['action'] ) {
			check_admin_referer( 'my_plugin_abort_nonce' );
			delete_site_option( 'my_plugin_job_in_progress' );
		}
	}

	// ok: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
	// Sink is not in the known state-mutating function list (a read, not a write) —
	// falls outside this pattern's scope.
	public function handle_status_check() {
		if ( $_REQUEST["action"] == "check_status" ) {
			get_option( 'my_plugin_job_in_progress' );
		}
	}

	// TP: switch/case dispatch table on a nested-array action key (a sub-array
	// of request options), first case invokes a static controller method, no
	// capability check anywhere in the function — the exact router-on-init shape
	// behind an unauthenticated full-database-export disclosure.
	public function route() {
		// ruleid: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
		if ( isset( $_POST['options']['action'] ) && ( $action = $_POST['options']['action'] ) ) {
			switch ( $action ) {
				case 'export':
					Export_Controller::export();
					break;

				case 'staging':
					Staging_Controller::deploy();
					break;
			}
		}
	}

	// TP: same switch-table shape, but the sink case is the second arm (one
	// other case precedes it) and dispatches through an instance method call
	// instead of a static one.
	public function route_secondary() {
		// ruleid: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
		if ( isset( $_REQUEST["action"] ) ) {
			switch ( $_REQUEST["action"] ) {
				case 'ping':
					echo 'pong';
					break;

				case 'export':
					$this->exportDatabase();
					break;
			}
		}
	}

	// ok: claude.php.wordpress.access-control.raw-request-action-dispatch-no-auth
	// Same nested-array switch-table shape, but the sensitive case is gated by
	// current_user_can() before invoking the sink — the fix this rule verifies.
	public function route_fixed() {
		if ( isset( $_POST['options']['action'] ) && ( $action = $_POST['options']['action'] ) ) {
			switch ( $action ) {
				case 'export':
					if ( current_user_can( 'export' ) ) {
						Export_Controller::export();
					}
					break;

				case 'staging':
					break;
			}
		}
	}

	public function exportDatabase() {}
}

class Export_Controller {
	public static function export() {}
}

class Staging_Controller {
	public static function deploy() {}
}
