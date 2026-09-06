<?php

// --- TRUE POSITIVES ---

function load_template_file_exists_tp1($template) {
    $path = PLUGIN_DIR . '/templates/' . $template . '.php';
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    if (file_exists($path)) {
        include $path;
    }
}

function load_template_is_file_tp2($template) {
    $path = PLUGIN_DIR . '/templates/' . $template . '.php';
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    if (is_file($path)) {
        require $path;
    }
}

function load_require_once_tp3($file) {
    $path = PLUGIN_DIR . '/' . $file;
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    if (file_exists($path)) {
        require_once($path);
    }
}

function load_include_once_tp4($tpl) {
    $path = PLUGIN_DIR . '/views/' . $tpl . '.php';
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    if (file_exists($path)) {
        include_once $path;
    }
}

// --- FALSE POSITIVES (real sanitizer present) ---

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_template_with_basename_fp1($template) {
    $safe = basename($template);
    $path = PLUGIN_DIR . '/templates/' . $safe . '.php';
    if (file_exists($path)) {
        include $path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_template_with_sanitize_fp2($template) {
    $safe = sanitize_file_name($template);
    $path = PLUGIN_DIR . '/templates/' . $safe . '.php';
    if (file_exists($path)) {
        include $path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_template_with_realpath_fp3($template) {
    $path = PLUGIN_DIR . '/templates/' . $template . '.php';
    $real = realpath($path);
    if (file_exists($path)) {
        include $path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_template_with_validate_file_fp4($template) {
    $path = PLUGIN_DIR . '/templates/' . $template . '.php';
    if (validate_file($path) === 0 && file_exists($path)) {
        include $path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_template_with_sanitize_key_fp5($template) {
    $safe = sanitize_key($template);
    $path = PLUGIN_DIR . '/templates/' . $safe . '.php';
    if (file_exists($path)) {
        include $path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_lib_fp6() {
    if (file_exists($this->lib_path)) {
        require_once $this->lib_path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_build_asset_fp7() {
    if (file_exists(__DIR__ . '/../build/asset.php')) {
        require __DIR__ . '/../build/asset.php';
    }
}

// --- Group 3: ternary-assignment-then-truthy-include ---

// ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
function get_template_part_tp5($slug) {
    $template = '';
    $fallback = PLUGIN_DIR . "/templates/{$slug}.php";
    $template = file_exists($fallback) ? $fallback : '';
    if ($template) {
        include $template;
    }
}

// ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
function get_template_part_tp6($name) {
    $candidate = PLUGIN_DIR . "/views/{$name}.php";
    $view = is_file($candidate) ? $candidate : '';
    if ($view) {
        require_once $view;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function get_template_part_with_sanitize_fp8($slug) {
    $slug = sanitize_file_name($slug);
    $template = '';
    $fallback = PLUGIN_DIR . "/templates/{$slug}.php";
    $template = file_exists($fallback) ? $fallback : '';
    if ($template) {
        include $template;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function get_template_part_with_basename_fp9($name) {
    $name = basename($name);
    $candidate = PLUGIN_DIR . "/views/{$name}.php";
    $view = is_file($candidate) ? $candidate : '';
    if ($view) {
        require_once $view;
    }
}
