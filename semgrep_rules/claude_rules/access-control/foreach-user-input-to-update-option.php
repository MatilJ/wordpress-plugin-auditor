<?php

// --- TRUE POSITIVES ---

function save_all_settings_tp1() {
    // ruleid: claude.php.wordpress.access-control.foreach-user-input-to-update-option
    foreach ($_POST as $key => $value) {
        if ($key !== 'action' && $key !== 'nonce') {
            update_option($key, $value);
        }
    }
}

function save_settings_from_request_tp2() {
    // ruleid: claude.php.wordpress.access-control.foreach-user-input-to-update-option
    foreach ($_REQUEST as $key => $value) {
        update_option($key, sanitize_text_field($value));
    }
}

function save_nested_settings_tp3() {
    // ruleid: claude.php.wordpress.access-control.foreach-user-input-to-update-option
    foreach ($_POST['settings'] as $key => $value) {
        update_option($key, $value);
    }
}

function save_via_add_option_tp4() {
    // ruleid: claude.php.wordpress.access-control.foreach-user-input-to-update-option
    foreach ($_POST as $key => $value) {
        add_option($key, $value);
    }
}

// --- FALSE POSITIVES (ok) ---

function save_with_allowlist_ok1() {
    $allowed = array('color', 'font', 'layout');
    // ok: claude.php.wordpress.access-control.foreach-user-input-to-update-option
    foreach ($allowed as $key) {
        if (isset($_POST[$key])) {
            update_option('mytheme_' . $key, sanitize_text_field($_POST[$key]));
        }
    }
}

function save_hardcoded_keys_ok2() {
    $settings = get_option('my_settings', array());
    // ok: claude.php.wordpress.access-control.foreach-user-input-to-update-option
    foreach ($settings as $key => $value) {
        update_option($key, $value);
    }
}

function save_single_option_ok3() {
    // ok: claude.php.wordpress.access-control.foreach-user-input-to-update-option
    update_option('single_setting', $_POST['value']);
}
