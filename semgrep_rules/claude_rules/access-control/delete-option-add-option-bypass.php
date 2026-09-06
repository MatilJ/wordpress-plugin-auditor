<?php

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.access-control.delete-option-add-option-bypass
function save_option_via_delete_add($option_name, $option_value) {
    delete_option($option_name);
    add_option($option_name, $option_value);
}

// ruleid: claude.php.wordpress.access-control.delete-option-add-option-bypass
function handle_nopriv_install() {
    $opt = sanitize_text_field($_POST['option']);
    $val = sanitize_text_field($_POST['opt_value']);
    delete_option($opt);
    add_option($opt, $val, '', 'yes');
}

// ruleid: claude.php.wordpress.access-control.delete-option-add-option-bypass
function update_config_bypass($key, $value) {
    $option_key = 'config_' . $key;
    delete_option($option_key);
    add_option($option_key, $value);
}

// --- FALSE POSITIVES (ok) ---

// ok: claude.php.wordpress.access-control.delete-option-add-option-bypass
function reset_hardcoded_option() {
    delete_option('my_plugin_version');
    add_option('my_plugin_version', '2.0.0');
}

// ok: claude.php.wordpress.access-control.delete-option-add-option-bypass
function cleanup_and_set_default() {
    delete_option('my_plugin_activated');
    add_option('my_plugin_activated', '1');
}

// ok: claude.php.wordpress.access-control.delete-option-add-option-bypass
function migrate_option() {
    $old = get_option('old_setting');
    delete_option('old_setting');
    update_option('new_setting', $old);
}
