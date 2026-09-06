<?php
// Test file for realpath-no-containment-check rule

// ruleid: claude.php.wordpress.file.realpath-no-containment-check
function serve_download_bad_reassign($encrypted_file_path) {
    $file_path = decrypt_file_path($encrypted_file_path, get_option('secret_key'));
    $uploads_dir = wp_upload_dir();
    $allowed_directory = $uploads_dir['basedir'];
    $full_file_path = $allowed_directory . '/' . $file_path;

    // Unrelated strpos() check (HTTP Referer) -- must NOT be mistaken for a
    // path-containment check against $allowed_directory.
    $referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    if (strpos($referer, home_url()) !== 0) {
        wp_die('Unauthorized access');
    }

    if (file_exists($full_file_path)) {
        $full_file_path = realpath($full_file_path);
        if (!$full_file_path || !is_readable($full_file_path)) {
            wp_die('File not found or inaccessible.');
        }
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        readfile($full_file_path);
        exit;
    }
    wp_die('File not found');
}

// ruleid: claude.php.wordpress.file.realpath-no-containment-check
function serve_export_bad_direct($request_name) {
    $export_dir = get_option('export_directory');
    $resolved = realpath($export_dir . '/' . $request_name);
    if (!$resolved || !is_file($resolved)) {
        return false;
    }
    echo file_get_contents($resolved);
}

// ok: claude.php.wordpress.file.realpath-no-containment-check
function serve_download_good_strpos_containment($encrypted_file_path) {
    $file_path = decrypt_file_path($encrypted_file_path, get_option('secret_key'));
    $uploads_dir = wp_upload_dir();
    $allowed_directory = $uploads_dir['basedir'];
    $full_file_path = $allowed_directory . '/' . $file_path;

    if (file_exists($full_file_path)) {
        $full_file_path = realpath($full_file_path);
        if (!$full_file_path || !is_readable($full_file_path)) {
            wp_die('File not found or inaccessible.');
        }
        if (strpos($full_file_path, $allowed_directory) !== 0) {
            wp_die('Invalid file request.');
        }
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        readfile($full_file_path);
        exit;
    }
    wp_die('File not found');
}

// ok: claude.php.wordpress.file.realpath-no-containment-check
function serve_export_good_str_starts_with($request_name) {
    $export_dir = get_option('export_directory');
    $resolved = realpath($export_dir . '/' . $request_name);
    if (!$resolved || !str_starts_with($resolved, $export_dir)) {
        return false;
    }
    echo file_get_contents($resolved);
}

// ruleid: claude.php.wordpress.file.realpath-no-containment-check
function nd_booking_ss_rooms_bad($atts) {
    $settings = shortcode_atts(array('layout' => ''), $atts);
    $layout = ($settings['layout'] == '') ? 'layout-1' : 'layout-' . $settings['layout'];
    $layout_selected = dirname(__FILE__) . '/layout/' . $layout . '.php';
    include realpath($layout_selected);
}

// ruleid: claude.php.wordpress.file.realpath-no-containment-check
function widget_render_view_bad($view) {
    $base = plugin_dir_path(__FILE__);
    $view_path = $base . $view;
    require realpath($view_path);
}

// ok: claude.php.wordpress.file.realpath-no-containment-check
function nd_booking_ss_rooms_good($atts) {
    $settings = shortcode_atts(array('layout' => ''), $atts);
    $layout = ($settings['layout'] == '') ? 'layout-1' : 'layout-' . $settings['layout'];
    $layout_selected = dirname(__FILE__) . '/layout/' . $layout . '.php';

    if (str_contains($layout_selected, '/wp-content/plugins/nd-booking/addons/shortcodes/rooms/layout/layout-1.php')) {
        include realpath($layout_selected);
    }
    if (str_contains($layout_selected, '/wp-content/plugins/nd-booking/addons/shortcodes/rooms/layout/layout-2.php')) {
        include realpath($layout_selected);
    }
}

// ok: claude.php.wordpress.file.realpath-no-containment-check
function widget_render_view_good($view) {
    $base = plugin_dir_path(__FILE__);
    $allowed = array('grid.php', 'list.php');
    if (!in_array($view, $allowed, true)) {
        return;
    }
    $view_path = $base . $view;
    require realpath($view_path);
}

// ruleid: claude.php.wordpress.file.realpath-no-containment-check
function lpie_admin_view_bad($name, $args = '') {
    if (!preg_match('~.php$~', $name)) {
        $name .= '.php';
    }
    if (is_array($args)) {
        extract($args);
    }

    $path = realpath(MY_PLUGIN_VIEWS_DIR . "admin/{$name}.php");
    if (!$path || !file_exists($path)) {
        return;
    }

    include $path;
}

// ok: claude.php.wordpress.file.realpath-no-containment-check
function lpie_admin_view_good($name, $args = '') {
    if (!preg_match('~.php$~', $name)) {
        $name .= '.php';
    }
    if (is_array($args)) {
        extract($args);
    }

    $path = realpath(MY_PLUGIN_VIEWS_DIR . "admin/{$name}.php");
    if (!$path || !file_exists($path)) {
        return;
    }

    $path = preg_replace('/\.\.+/', '', $path);

    include $path;
}
