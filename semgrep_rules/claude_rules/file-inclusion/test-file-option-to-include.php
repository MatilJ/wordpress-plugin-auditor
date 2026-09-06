<?php

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.file.option-to-include
function load_stored_template_tp1() {
    $template = get_option('my_plugin_template');
    include PLUGIN_DIR . '/templates/' . $template . '.php';
}

// ruleid: claude.php.wordpress.file.option-to-include
function load_post_meta_template_tp2($post_id) {
    $tpl = get_post_meta($post_id, '_custom_template', true);
    load_template($tpl);
}

// ruleid: claude.php.wordpress.file.option-to-include
function load_user_meta_template_tp3($user_id) {
    $path = get_user_meta($user_id, 'dashboard_template', true);
    require $path;
}

// ruleid: claude.php.wordpress.file.option-to-include
function load_transient_template_tp4() {
    $cached_tpl = get_transient('active_template_path');
    include_once($cached_tpl);
}

// ruleid: claude.php.wordpress.file.option-to-include
function load_site_option_template_tp5() {
    $template = get_site_option('network_template');
    require_once $template;
}

// --- FALSE POSITIVES (sanitized) ---

// ok: claude.php.wordpress.file.option-to-include
function load_stored_template_sanitized_fp1() {
    $template = sanitize_file_name(get_option('my_plugin_template'));
    include PLUGIN_DIR . '/templates/' . $template . '.php';
}

// ok: claude.php.wordpress.file.option-to-include
function load_stored_template_basename_fp2() {
    $template = basename(get_option('my_plugin_template'));
    include PLUGIN_DIR . '/templates/' . $template . '.php';
}

// ok: claude.php.wordpress.file.option-to-include
function load_stored_template_sanitize_key_fp3() {
    $template = sanitize_key(get_post_meta($post_id, '_tpl', true));
    include PLUGIN_DIR . '/templates/' . $template . '.php';
}

// ok: claude.php.wordpress.file.option-to-include
function load_stored_template_intval_fp4() {
    $id = intval(get_option('template_id'));
    include PLUGIN_DIR . '/templates/tpl-' . $id . '.php';
}
