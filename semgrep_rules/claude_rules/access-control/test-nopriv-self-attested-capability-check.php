<?php
// Test file for nopriv-self-attested-capability-check rule

// --- TRUE POSITIVES ---

// TP1: nopriv-registered handler; a sibling method in the same class decides
// authorization from a client-supplied "cap" POST field via a wrapper around
// current_user_can() (mirrors CVE-2026-39587's check_cap()/is_capable() split).
class WpB_Edit_Addon_Vuln {

	public function add_hooks() {
		add_action( 'wp_ajax_open_edit_dialog', array( $this, 'open_dialog' ) );
		add_action( 'wp_ajax_nopriv_open_dialog', array( $this, 'open_dialog' ) );
	}

	public function open_dialog() {
		$booking = get_booking( (int) $_REQUEST['app_id'] );
		$this->check_cap( $booking );
		die( json_encode( array( 'success' => true ) ) );
	}

	private function check_cap( $booking ) {
		// ruleid: claude.php.wordpress.access-control.nopriv-self-attested-capability-check
		$can_edit = ! empty( $_POST['cap'] ) && BASE( 'User' )->is_capable( wpb_clean( $_POST['cap'] ) );

		if ( ! ( $can_edit || $this->is_owner( $booking ) ) ) {
			die( json_encode( array( 'error' => 'unauthorised' ) ) );
		}
	}

	private function is_owner( $booking ) {
		return $booking->user == get_current_user_id();
	}
}

// TP2: admin_post_nopriv_ variant, capability name read straight from $_GET
// with no sanitizer wrapper, checked via bare current_user_can().
class Front_Export_Vuln {

	public function add_hooks() {
		add_action( 'admin_post_nopriv_export_report', array( $this, 'export' ) );
	}

	public function export() {
		$this->guard();
		echo build_report_csv();
	}

	private function guard() {
		// ruleid: claude.php.wordpress.access-control.nopriv-self-attested-capability-check
		if ( ! current_user_can( $_GET['cap'] ) ) {
			wp_die( 'Unauthorized' );
		}
	}
}

// --- TRUE NEGATIVES ---

// TN1: nopriv hook present, but the capability check uses a hardcoded string —
// the fix shape (no request-derived capability name reaches the check at all).
class WpB_Edit_Addon_Fixed {

	public function add_hooks() {
		add_action( 'wp_ajax_open_edit_dialog', array( $this, 'open_dialog' ) );
		add_action( 'wp_ajax_nopriv_open_dialog', array( $this, 'open_dialog' ) );
	}

	public function open_dialog() {
		$booking = get_booking( (int) $_REQUEST['app_id'] );
		$this->check_cap( $booking );
		die( json_encode( array( 'success' => true ) ) );
	}

	// ok: claude.php.wordpress.access-control.nopriv-self-attested-capability-check
	private function check_cap( $booking ) {
		$can_edit = current_user_can( 'edit_others_posts' );

		if ( ! ( $can_edit || $this->is_owner( $booking ) ) ) {
			die( json_encode( array( 'error' => 'unauthorised' ) ) );
		}
	}

	private function is_owner( $booking ) {
		return $booking->user == get_current_user_id();
	}
}

// TN2: request-derived capability name IS used, but the class never registers
// a nopriv/nopriv admin-post hook — every reachable path requires login, so
// current_user_can() never runs for a fully anonymous visitor.
class Admin_Only_Edit_Panel {

	public function add_hooks() {
		add_action( 'wp_ajax_edit_dialog', array( $this, 'open_dialog' ) );
	}

	public function open_dialog() {
		$booking = get_booking( (int) $_REQUEST['app_id'] );
		$this->check_cap( $booking );
		die( json_encode( array( 'success' => true ) ) );
	}

	// ok: claude.php.wordpress.access-control.nopriv-self-attested-capability-check
	private function check_cap( $booking ) {
		$can_edit = ! empty( $_POST['cap'] ) && BASE( 'User' )->is_capable( wpb_clean( $_POST['cap'] ) );

		if ( ! ( $can_edit || $this->is_owner( $booking ) ) ) {
			die( json_encode( array( 'error' => 'unauthorised' ) ) );
		}
	}

	private function is_owner( $booking ) {
		return $booking->user == get_current_user_id();
	}
}

// TN3: nopriv hook present, and a request-derived capability name is checked,
// but it is validated against a hardcoded allow-list first — not a bare
// self-attested pass-through.
class Allowlisted_Edit_Addon {

	public function add_hooks() {
		add_action( 'wp_ajax_open_edit_dialog', array( $this, 'open_dialog' ) );
		add_action( 'wp_ajax_nopriv_open_dialog', array( $this, 'open_dialog' ) );
	}

	public function open_dialog() {
		$booking = get_booking( (int) $_REQUEST['app_id'] );
		$this->check_cap( $booking );
		die( json_encode( array( 'success' => true ) ) );
	}

	// ok: claude.php.wordpress.access-control.nopriv-self-attested-capability-check
	private function check_cap( $booking ) {
		$allowed = array( 'edit_own_booking', 'edit_own_profile' );

		if ( in_array( $_POST['cap'], $allowed, true ) && current_user_can( $_POST['cap'] ) ) {
			$can_edit = true;
		} else {
			$can_edit = false;
		}

		if ( ! ( $can_edit || $this->is_owner( $booking ) ) ) {
			die( json_encode( array( 'error' => 'unauthorised' ) ) );
		}
	}

	private function is_owner( $booking ) {
		return $booking->user == get_current_user_id();
	}
}
