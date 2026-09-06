<?php
/**
 * Test cases for claude.php.wordpress.auth.user-controlled-option-key
 *
 * TRUE POSITIVE: user-controlled input reaches the KEY argument of update_option()
 * or delete_option() — attacker can write to or delete any wp_options row.
 *
 * FALSE POSITIVE / OK: option name is constrained by a hardcoded prefix via string
 * concatenation or sprintf(), or is reduced to an allowlisted value.
 */

// ── MATCH: raw $_POST value used directly as option key ───────────────────────

function save_arbitrary_option_vulnerable() {
    $key   = $_POST['option_name'];
    $value = sanitize_text_field( $_POST['value'] );
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_option( $key, $value );
}

// ── MATCH: $_GET key used in delete_option ────────────────────────────────────

function delete_arbitrary_option_vulnerable() {
    $key = $_GET['key'];
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    delete_option( $key );
}

// ── MATCH: loop over POST array keys used as option names ─────────────────────

function save_batch_options_vulnerable() {
    foreach ( $_POST['settings'] as $key => $value ) {
        // ruleid: claude.php.wordpress.auth.user-controlled-option-key
        update_option( $key, sanitize_text_field( $value ) );
    }
}

// ── NO MATCH: hardcoded prefix via string concatenation (namespace-constrained) ─

function save_plugin_option_concat() {
    $key   = sanitize_key( $_POST['field'] );
    $value = sanitize_text_field( $_POST['value'] );
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option( 'myplugin_' . $key, $value );
}

// ── NO MATCH: hardcoded format string via sprintf() (namespace-constrained) ────

function dismiss_notice_sprintf() {
    $which = sanitize_key( $_POST['which'] );
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option( sprintf( 'myplugin_%s_notice_hidden', $which ), '1', false );
}

// ── NO MATCH: delete_option with sprintf-constrained key ─────────────────────

function remove_plugin_notice_sprintf() {
    $slug = sanitize_key( $_GET['slug'] );
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    delete_option( sprintf( 'myplugin_%s_dismissed', $slug ) );
}

// ── NO MATCH: sanitize_key() applied to user input before use as key ──────────

function save_sanitized_key_option() {
    $key   = sanitize_key( $_POST['option_name'] );
    $value = sanitize_text_field( $_POST['value'] );
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option( $key, $value );
}

// ── MATCH: AJAX-style handler with no allow-list before the write ─────────────

function ajax_save_setting_vulnerable() {
    $opt_name  = isset( $_POST['opt_name'] )  ? sanitize_text_field( $_POST['opt_name'] )  : null;
    $opt_value = isset( $_POST['opt_value'] ) ? sanitize_text_field( $_POST['opt_value'] ) : null;
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_option( $opt_name, $opt_value );
}

// ── NO MATCH: in_array() allow-list guard (with early return) before the write ─

function ajax_save_setting_fixed() {
    $opt_name  = isset( $_POST['opt_name'] )  ? sanitize_text_field( $_POST['opt_name'] )  : '';
    $opt_value = isset( $_POST['opt_value'] ) ? sanitize_text_field( $_POST['opt_value'] ) : '';
    $allowed_options = array( 'plugin_accountID', 'plugin_siteID', 'plugin_options' );
    if ( ! in_array( $opt_name, $allowed_options ) ) {
        wp_send_json_error( 'Invalid option name' );
        return;
    }
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option( $opt_name, $opt_value );
}

// ── NO MATCH: array_key_exists() allow-list guard before the write ────────────

function save_option_array_key_exists_guard() {
    $key     = $_POST['opt_name'];
    $allowed = array( 'foo_a' => true, 'foo_b' => true );
    if ( ! array_key_exists( $key, $allowed ) ) {
        return;
    }
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option( $key, $_POST['opt_value'] );
}

// ── NO MATCH: bare uppercase constant + literal + user suffix (namespace-constrained) ─

define( 'CNB_SLUG', 'call-now-button' );

function hide_notice_constant_prefix() {
    $dismiss_option = sanitize_text_field( filter_input( INPUT_POST, 'dismiss_option' ) );
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option( CNB_SLUG . '_dismissed_' . $dismiss_option, true );
}

// ── NO MATCH: bare uppercase constant directly concatenated with the suffix,
// no literal in between ────────────────────────────────────────────────────────

function delete_notice_constant_prefix_no_literal() {
    $key = sanitize_key( $_GET['key'] );
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    delete_option( CNB_SLUG . $key );
}

// ── MATCH: lowercase variable used as the "prefix" — NOT a constant, so the
// namespace is not actually fixed; must still be flagged ──────────────────────

function save_option_variable_prefix_vulnerable() {
    $ns  = sanitize_key( $_POST['namespace'] );
    $key = $_POST['field'];
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_option( $ns . '_setting_' . $key, $_POST['value'] );
}
