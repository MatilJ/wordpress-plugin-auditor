<?php

function myplugin_render_quarantine_page() {
	global $wpdb;
	// ruleid: claude.php.wordpress.access-control.custom-nonce-store-no-context-binding
	if (isset($_REQUEST["page"]) && $_REQUEST["page"] == "myplugin_restore" && isset($_REQUEST["mp_token"]) && strlen($_REQUEST["mp_token"]) == 32 && isset($GLOBALS["myplugin"]["nonce"][$_REQUEST["mp_token"]])) {
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}myplugin_quarantine WHERE id = %d", (int) $_REQUEST["id"]));
		file_put_contents($row->file_path, base64_decode($row->file_contents));
	}
}

function myplugin_get_verify_token() {
	// ruleid: claude.php.wordpress.access-control.custom-nonce-store-no-context-binding
	if (isset($_GET["mp_nonce"]) && array_key_exists($_GET["mp_nonce"], $GLOBALS["myplugin_token_store"])) {
		return $GLOBALS["myplugin_token_store"][$_GET["mp_nonce"]];
	}
	return false;
}

function myplugin_get_nonce($action = "") {
	// The fix for this bug class: fetch the stored entry once, then
	// separately require its recorded "context" to match the caller's
	// intended action before trusting the bare membership check.
	// ok: claude.php.wordpress.access-control.custom-nonce-store-no-context-binding
	if (isset($GLOBALS["myplugin"]["nonce"][$_REQUEST["mp_token"]]))
		$token = $GLOBALS["myplugin"]["nonce"][$_REQUEST["mp_token"]];
	if (is_array($token) && isset($token["context"]) && ($token["context"] == $action)) {
		return $token["hour"];
	}
	return false;
}

function myplugin_get_scan_log($id) {
	global $wpdb;
	// ok: claude.php.wordpress.access-control.custom-nonce-store-no-context-binding
	$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}myplugin_log WHERE id = %d", $id));
	return $row;
}
