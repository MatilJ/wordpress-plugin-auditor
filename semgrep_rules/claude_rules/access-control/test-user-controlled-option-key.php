<?php

// ---- TRUE POSITIVES ----

function tp_direct_post_key() {
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_option($_POST['option_name'], $_POST['value']);
}

function tp_variable_post_key() {
    $key = $_POST['key'];
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_option($key, 'some_value');
}

function tp_delete_with_user_key() {
    $option = $_GET['delete_option'];
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    delete_option($option);
}

function tp_add_option_user_key() {
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    add_option($_REQUEST['opt'], 'default');
}

function tp_rest_param_key($request) {
    $key = $request->get_param('option_key');
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_option($key, $request->get_param('value'));
}

function tp_site_option_user_key() {
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_site_option($_POST['site_opt'], $_POST['val']);
}

// ---- FALSE POSITIVES ----

function ok_hardcoded_key() {
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option('my_plugin_settings', $_POST['value']);
}

function ok_hardcoded_delete() {
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    delete_option('my_plugin_cache');
}

function ok_sanitize_key_on_name() {
    $key = sanitize_key($_POST['key']);
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option($key, 'value');
}

function ok_integer_key() {
    $id = intval($_POST['id']);
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option($id, 'value');
}

// ─── HARDCODED PREFIX SUPPRESSION (woo-smart-wishlist FP pattern) ─────────────
// update_option('prefix_' . $user_var) constrains the namespace — the user-
// controlled suffix cannot form critical WP option names when a non-trivial
// literal prefix is prepended. Confirmed FP: woo-smart-wishlist 6.0.0 lines 404/463.

// sanitize_text_field is NOT a sanitizer in this rule — $key stays tainted.
// With a bare variable, the rule should still fire.
function tp_sanitize_text_field_not_sanitizer() {
    $key = sanitize_text_field($_POST['option_name']);
    // ruleid: claude.php.wordpress.auth.user-controlled-option-key
    update_option($key, $_POST['value']);
}

// Hardcoded prefix — option name namespace is limited; cannot reach critical WP options.
function ok_hardcoded_prefix_update() {
    $key = sanitize_text_field($_POST['key']);
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    update_option('woosw_list_' . $key, [], false);
}

// Same with add_option — prefix still constrains the namespace.
function ok_hardcoded_prefix_add() {
    $key = sanitize_text_field($_POST['key']);
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    add_option('myplugin_cache_' . $key, 'default');
}

// delete_option with hardcoded prefix — same safe constraint.
function ok_hardcoded_prefix_delete_option() {
    $key = sanitize_text_field($_POST['key']);
    // ok: claude.php.wordpress.auth.user-controlled-option-key
    delete_option('myplugin_temp_' . $key);
}
