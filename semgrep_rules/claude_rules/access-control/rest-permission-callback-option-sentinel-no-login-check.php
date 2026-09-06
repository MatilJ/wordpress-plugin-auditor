<?php

// Test cases for
// claude.php.wordpress.access-control.rest-permission-callback-option-sentinel-no-login-check

class TicketScanner {

	private $onlyLoggedInScannerAllowed = false;

	// TP: canonical CVE-2025-68015 shape — option compared to a sentinel
	// gates an early `return true;`, and the function never checks
	// is_user_logged_in() anywhere. Unauthenticated visitors pass when the
	// site is left at the (common/default) "no role restriction" setting.
	// ruleid: claude.php.wordpress.access-control.rest-permission-callback-option-sentinel-no-login-check
	function rest_permission_callback($web_request) {
		$ret = false;
		$allowed_role = $this->options->getOptionValue('scannerAllowedRoles');
		if (!$this->onlyLoggedInScannerAllowed && $allowed_role == "-") return true;
		$user = wp_get_current_user();
		$user_roles = (array) $user->roles;
		if ($allowed_role != "-") {
			if (in_array($allowed_role, $user_roles)) $ret = true;
		}
		return $ret;
	}

	// TP: same shape, braced return-true form.
	// ruleid: claude.php.wordpress.access-control.rest-permission-callback-option-sentinel-no-login-check
	function rest_permission_callback_braced($web_request) {
		$mode = $this->settings->getSettingValue('accessMode');
		if ($mode == "open") {
			do_something();
			return true;
		}
		return false;
	}

	// This is the actual 2.8.6 fix: is_user_logged_in() is checked
	// unconditionally before the option-driven branch can ever run, so the
	// function is excluded even though the option-comparison shape remains.
	// ok: claude.php.wordpress.access-control.rest-permission-callback-option-sentinel-no-login-check
	function rest_permission_callback_fixed($web_request) {
		if (!is_user_logged_in()) return false;
		$user = wp_get_current_user();
		$user_roles = (array) $user->roles;
		if (in_array("administrator", $user_roles)) return true;
		$ret = false;
		$allowed_role = $this->options->getOptionValue('scannerAllowedRoles');
		if ($allowed_role == "-") {
			$ret = true;
		} else {
			$ret = in_array($allowed_role, $user_roles);
		}
		return $ret;
	}

	// A real capability check anywhere in the function excludes it,
	// even though the option/sentinel/return-true shape is also present.
	// ok: claude.php.wordpress.access-control.rest-permission-callback-option-sentinel-no-login-check
	function rest_permission_callback_with_cap($web_request) {
		$mode = $this->options->getOptionValue('accessMode');
		if ($mode == "open" && current_user_can('read')) {
			return true;
		}
		return false;
	}

	// Getter name has nothing to do with option/setting/config, so the
	// $GETTER metavariable-regex excludes it (out of this rule's scope).
	// ok: claude.php.wordpress.access-control.rest-permission-callback-option-sentinel-no-login-check
	function rest_permission_callback_unrelated_getter($web_request) {
		$mode = $this->helper->fetchStatus('accessMode');
		if ($mode == "open") return true;
		return false;
	}

	// Comparison value is not a string literal (a variable), so the
	// $SENTINEL metavariable-regex excludes it.
	// ok: claude.php.wordpress.access-control.rest-permission-callback-option-sentinel-no-login-check
	function rest_permission_callback_variable_compare($web_request) {
		$mode = $this->options->getOptionValue('accessMode');
		$expected = get_option('expected_mode');
		if ($mode == $expected) return true;
		return false;
	}
}
