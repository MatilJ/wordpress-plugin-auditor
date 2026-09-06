<?php
// Test file for directory-archive-no-containment-check rule

// ruleid: claude.php.wordpress.file.directory-archive-no-containment-check
function zip_theme_by_slug($stylesheet) {
    $directories = get_plugin_directories();
    $uploads = $directories['uploads'];
    $source_directory = get_theme_root() . '/' . $stylesheet; // Get theme path
    if (zip_directory_to_uploads($source_directory, $uploads)) {
        return 'Theme ' . $stylesheet . ' zipped successfully!';
    }
    return false;
}

// ruleid: claude.php.wordpress.file.directory-archive-no-containment-check
function zip_plugin_by_slug($slug) {
    $directories = get_plugin_directories();
    $uploads = $directories['uploads'];
    $source_directory = trailingslashit(dirname(plugin_dir_path(__FILE__))) . $slug;
    zip_directory_to_uploads($source_directory, $uploads);
}

// ok: claude.php.wordpress.file.directory-archive-no-containment-check
function zip_theme_by_slug_capability_checked($stylesheet) {
    if (!current_user_can('manage_options')) {
        return;
    }
    $directories = get_plugin_directories();
    $uploads = $directories['uploads'];
    $source_directory = get_theme_root() . '/' . $stylesheet;
    if (zip_directory_to_uploads($source_directory, $uploads)) {
        return 'Theme ' . $stylesheet . ' zipped successfully!';
    }
    return false;
}

// ok: claude.php.wordpress.file.directory-archive-no-containment-check
function zip_theme_by_slug_basename_sanitized($stylesheet) {
    $stylesheet = basename($stylesheet);
    $directories = get_plugin_directories();
    $uploads = $directories['uploads'];
    $source_directory = get_theme_root() . '/' . $stylesheet;
    if (zip_directory_to_uploads($source_directory, $uploads)) {
        return 'Theme ' . $stylesheet . ' zipped successfully!';
    }
    return false;
}

// ok: claude.php.wordpress.file.directory-archive-no-containment-check
function get_theme_demo_rows($stylesheet) {
    global $wpdb;
    $stylesheet = sanitize_text_field($stylesheet);
    $rows = $wpdb->get_results(
        $wpdb->prepare("SELECT * FROM %i WHERE stylesheet = %s", $wpdb->prefix . 'theme_demos', $stylesheet)
    );
    return $rows;
}
