<?php

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function render_template($name) {
    include PLUGIN_DIR . '/templates/' . $name . '.php';
}

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function load_view($view) {
    $path = PLUGIN_DIR . '/views/' . $view;
    require $path;
}

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function get_partial($partial_name) {
    include_once PLUGIN_DIR . '/partials/' . $partial_name . '.php';
}

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function load_template_file($template) {
    include($template);
}

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function locate_template($names) {
    require_once PLUGIN_DIR . '/templates/' . $names . '.php';
}

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function wc_get_template($template_name) {
    include PLUGIN_DIR . '/templates/' . $template_name;
}

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function get_template($tpl) {
    include PLUGIN_DIR . '/templates/' . $tpl . '.php';
}

// ruleid: claude.php.wordpress.file.custom-template-wrapper
function include_template($name) {
    require PLUGIN_DIR . '/templates/' . $name . '.php';
}

// --- FALSE NEGATIVES (function name doesn't match pattern) ---

// ok: claude.php.wordpress.file.custom-template-wrapper
function process_data($path) {
    include $path;
}

// ok: claude.php.wordpress.file.custom-template-wrapper
function handle_upload($file) {
    include $file;
}

// ok: claude.php.wordpress.file.custom-template-wrapper
function render() {
    require __DIR__ . '/view.php';
}

// ok: claude.php.wordpress.file.custom-template-wrapper
function render_page() {
    include_once PLUGIN_DIR . '/admin/page.php';
}

// ok: claude.php.wordpress.file.custom-template-wrapper
function render_block($attrs, $content) {
    include __DIR__ . '/block.php';
}

// ok: claude.php.wordpress.file.custom-template-wrapper
function render_menu_page() {
    require_once __DIR__ . '/view.php';
}

// ok: claude.php.wordpress.file.custom-template-wrapper
function users_overview() {
    include PLUGIN_DIR . '/admin/overview.php';
}

// ok: claude.php.wordpress.file.custom-template-wrapper
function is_cpt_custom_templates_supported() {
    require_once ABSPATH . '/wp-admin/includes/theme.php';
    return method_exists(wp_get_theme(), 'get_post_templates');
}
