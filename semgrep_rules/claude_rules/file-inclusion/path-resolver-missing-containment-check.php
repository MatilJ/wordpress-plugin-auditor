<?php

// Test cases for claude.php.wordpress.file.path-resolver-missing-containment-check

// True positive — resolver returns the raw concatenation with no
// realpath()/containment check.
// ruleid: claude.php.wordpress.file.path-resolver-missing-containment-check
function getOriginalPath($url) {
    $path = str_replace(home_url(), '', $url);
    return getRootPath() . ltrim($path, '/');
}

// True positive — path_join() shape, no containment check on the result.
// ruleid: claude.php.wordpress.file.path-resolver-missing-containment-check
function generate_user_filepath($form_id, $name, $filename) {
    $dir = get_user_dir($form_id, $name);
    return path_join($dir, $filename);
}

// False positive — realpath() + prefix check before returning.
function getSafePath($base, $path) {
    $resolved = realpath($base . ltrim($path, '/'));
    if (strpos($resolved, $base) !== 0) {
        return false;
    }
    // ok: claude.php.wordpress.file.path-resolver-missing-containment-check
    return $resolved;
}

// False positive — the remainder is stripped to a bare filename via
// wp_basename() (on a differently-named variable) before the join, so no
// traversal segment can survive into the joined result regardless of which
// local variable reaches the join/return call.
function gutenberg_get_animated_gif_companion_path($attachment_id, $meta_key) {
    $metadata = wp_get_attachment_metadata($attachment_id, true);
    $name = wp_basename($metadata[$meta_key]);
    $attached_file = get_attached_file($attachment_id, true);
    // ok: claude.php.wordpress.file.path-resolver-missing-containment-check
    return path_join(dirname($attached_file), $name);
}

// Same false positive via plain basename() instead of wp_basename().
function get_companion_path($base_dir, $stored_name) {
    $name = basename($stored_name);
    // ok: claude.php.wordpress.file.path-resolver-missing-containment-check
    return path_join($base_dir, $name);
}
