<?php

// Legacy create_function()-based regex callback: static delimiter, decoded
// capture group fed straight into file_get_contents() with no validation.
function inject_minified_content($buffer) {
    if (strpos($buffer, '%%INJECTLATER%%') !== false) {
        $out = preg_replace_callback(
            '#%%INJECTLATER%%(.*?)%%INJECTLATER%%#is',
            create_function(
                '$matches',
                // ruleid: claude.php.wordpress.file.static-marker-decoded-path-file-read
                '$filepath = base64_decode(strtok($matches[1], "|"));
                $filecontent = file_get_contents($filepath);
                return $filecontent;'
            ),
            $buffer
        );
    }
    return $out;
}

// Modern closure equivalent of the same idiom.
function restore_asset_placeholder($buffer) {
    return preg_replace_callback('#%%ASSET%%(.*?)%%ASSET%%#is', function ($matches) {
        // ruleid: claude.php.wordpress.file.static-marker-decoded-path-file-read
        $path = base64_decode($matches[1]);
        return readfile($path);
    }, $buffer);
}

// Fixed: delimiter now concatenates in a per-request unpredictable value, so
// the marker cannot be forged by content the code did not itself just encode.
function restore_asset_placeholder_fixed($buffer) {
    $secret = wp_hash(AUTH_KEY . microtime());
    return preg_replace_callback('#%%ASSET' . $secret . '%%(.*?)%%ASSET%%#is', function ($matches) {
        // ok: claude.php.wordpress.file.static-marker-decoded-path-file-read
        $path = base64_decode($matches[1]);
        return readfile($path);
    }, $buffer);
}

// Fixed differently: delimiter still static, but the decoded path is
// canonicalized and containment-checked before use.
function restore_asset_placeholder_sanitized($buffer) {
    return preg_replace_callback('#%%ASSET%%(.*?)%%ASSET%%#is', function ($matches) {
        // ok: claude.php.wordpress.file.static-marker-decoded-path-file-read
        $path = base64_decode($matches[1]);
        $real = realpath($path);
        if (0 !== strpos($real, WP_CONTENT_DIR)) {
            return '';
        }
        return file_get_contents($real);
    }, $buffer);
}

// Unrelated WP DB read — must not trigger this rule.
function get_cached_rows() {
    global $wpdb;
    // ok: claude.php.wordpress.file.static-marker-decoded-path-file-read
    return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}my_table WHERE status = 'active'");
}
