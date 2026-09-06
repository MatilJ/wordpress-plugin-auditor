<?php
// Test file for shortcode-attr-to-include rule

function bad_shortcode_include($atts) {
    $template = $atts['template'];
    // ruleid: claude.php.wordpress.lfi.shortcode-attr-to-include
    include PLUGIN_DIR . '/templates/' . $template . '.php';
}

function bad_widget_include($instance) {
    $tpl = $instance['template_file'];
    // ruleid: claude.php.wordpress.lfi.shortcode-attr-to-include
    load_template($tpl);
}

function bad_block_include($attributes) {
    $view = $attributes['view'];
    // ruleid: claude.php.wordpress.lfi.shortcode-attr-to-include
    require PLUGIN_DIR . '/views/' . $view . '.php';
}

function bad_args_include($args) {
    $path = $args['extra_template_path'];
    // ruleid: claude.php.wordpress.lfi.shortcode-attr-to-include
    include $path;
}

function bad_settings_include($settings) {
    $layout = $settings['layout'];
    // ruleid: claude.php.wordpress.lfi.shortcode-attr-to-include
    include_once PLUGIN_DIR . '/layouts/' . $layout . '.php';
}

function good_shortcode_sanitized($atts) {
    $name = sanitize_file_name($atts['template']);
    // ok: claude.php.wordpress.lfi.shortcode-attr-to-include
    include PLUGIN_DIR . '/templates/' . $name . '.php';
}

function good_shortcode_basename($atts) {
    $file = basename($atts['file']);
    // ok: claude.php.wordpress.lfi.shortcode-attr-to-include
    include PLUGIN_DIR . '/templates/' . $file;
}

function good_shortcode_sanitize_key($atts) {
    $tpl = sanitize_key($atts['template']);
    // ok: claude.php.wordpress.lfi.shortcode-attr-to-include
    include PLUGIN_DIR . '/templates/' . $tpl . '.php';
}

function good_shortcode_intval($atts) {
    $id = intval($atts['template_id']);
    // ok: claude.php.wordpress.lfi.shortcode-attr-to-include
    include PLUGIN_DIR . '/templates/template-' . $id . '.php';
}

function good_shortcode_array_key_exists_ternary($atts) {
    $designs = array('design-1' => 1, 'design-2' => 1);
    $atts['design'] = ( $atts['design'] && ( array_key_exists( trim( $atts['design'] ), $designs ) ) ) ? trim( $atts['design'] ) : 'design-1';
    // ok: claude.php.wordpress.lfi.shortcode-attr-to-include
    include PLUGIN_DIR . '/templates/masonry/' . $atts['design'] . '.php';
}

function good_shortcode_array_key_exists_ternary_simple($atts) {
    $allowed = array('grid' => 1, 'list' => 1);
    $layout = array_key_exists($atts['layout'], $allowed) ? $atts['layout'] : 'grid';
    // ok: claude.php.wordpress.lfi.shortcode-attr-to-include
    include PLUGIN_DIR . '/templates/' . $layout . '.php';
}
