<?php
// Test file: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// VULNERABLE: $_POST result_id flows to $wpdb->delete WHERE clause
function vuln_delete_quiz_result() {
    global $wpdb;
    check_ajax_referer('delete_result', 'nonce');
    $result_id = intval($_POST['result_id']);
    // ruleid: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth
    $wpdb->delete($wpdb->prefix . 'quiz_results', array('id' => $result_id));
}

// VULNERABLE: $_GET entry_id flows to $wpdb->delete
function vuln_delete_form_entry() {
    global $wpdb;
    $entry_id = absint($_GET['entry_id']);
    // ruleid: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth
    $wpdb->delete($wpdb->prefix . 'form_entries', array('entry_id' => $entry_id), array('%d'));
}

// VULNERABLE: $_REQUEST id flows to $wpdb->delete
function vuln_delete_booking() {
    global $wpdb;
    $id = (int) $_REQUEST['id'];
    // ruleid: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth
    $wpdb->delete($wpdb->prefix . 'bookings', array('booking_id' => $id));
}

// VULNERABLE: REST param flows to $wpdb->delete
function vuln_rest_delete_record($request) {
    global $wpdb;
    $record_id = $request->get_param('id');
    // ruleid: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth
    $wpdb->delete($wpdb->prefix . 'custom_records', array('id' => $record_id));
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: hardcoded WHERE values (cleanup)
function safe_hardcoded_delete() {
    global $wpdb;
    // ok: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth
    $wpdb->delete($wpdb->prefix . 'cache_table', array('expired' => 1));
}

// SAFE: ID from DB query (taint broken)
function safe_db_sourced_delete() {
    global $wpdb;
    $id = $wpdb->get_var("SELECT id FROM {$wpdb->prefix}records WHERE status = 'expired' LIMIT 1");
    // ok: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth
    $wpdb->delete($wpdb->prefix . 'records', array('id' => $id));
}

// SAFE: ID from get_option (taint broken)
function safe_option_sourced_delete() {
    global $wpdb;
    $page_id = get_option('plugin_orphan_page');
    // ok: claude.php.wordpress.access-control.ajax-request-id-to-wpdb-delete-no-auth
    $wpdb->delete($wpdb->prefix . 'pages', array('id' => $page_id));
}
