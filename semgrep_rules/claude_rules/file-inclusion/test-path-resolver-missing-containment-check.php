<?php
// Test file for path-resolver-missing-containment-check rule

// ruleid: claude.php.wordpress.file.path-resolver-missing-containment-check
function getOriginalPath_bad_assign($new_url) {
    $new_path = str_replace(home_url(), '', $new_url);
    if (strpos($new_path, '?') !== false) {
        $new_path = substr($new_path, 0, strpos($new_path, '?'));
    }
    $resolved = getRootPath() . ltrim($new_path, '/');
    return $resolved;
}

// ruleid: claude.php.wordpress.file.path-resolver-missing-containment-check
function resolve_asset_path_bad_direct($request_path) {
    $rel = str_replace(site_url(), '', $request_path);
    return WP_CONTENT_DIR . ltrim($rel, '/');
}

// ok: claude.php.wordpress.file.path-resolver-missing-containment-check
function getOriginalPath_good_realpath_containment($new_url) {
    $new_path = str_replace(home_url(), '', $new_url);
    $root = getRootPath();
    $resolved = realpath($root . ltrim($new_path, '/'));
    $resolved = str_replace('\\', '/', $resolved);
    if (strpos($resolved, $root) === false) {
        return false;
    }
    return $resolved;
}

// ok: claude.php.wordpress.file.path-resolver-missing-containment-check
function resolve_asset_path_good_validate_file($request_path) {
    $rel = str_replace(site_url(), '', $request_path);
    if (0 !== validate_file($rel)) {
        return false;
    }
    return WP_CONTENT_DIR . ltrim($rel, '/');
}

class Directory_Helper_Bad_Blacklist_Only {
    // ruleid: claude.php.wordpress.file.path-resolver-missing-containment-check
    public static function generate_user_filepath($form_id, $name, $filename) {
        if (!$filename) {
            return false;
        }
        $user_file_dir = static::generate_user_file_dirpath($form_id, $name);
        if (!$user_file_dir || !is_dir($user_file_dir)) {
            return false;
        }
        $filepath = path_join($user_file_dir, $filename);
        if (str_contains($filepath, '../') || str_contains($filepath, '..' . DIRECTORY_SEPARATOR)) {
            throw new \RuntimeException('Invalid file reference requested.');
        }
        if (strstr($filepath, "\0")) {
            throw new \RuntimeException('Invalid file reference requested.');
        }
        return $filepath;
    }
}

// ruleid: claude.php.wordpress.file.path-resolver-missing-containment-check
function get_report_path_bad_direct_return($base_dir, $requested_name) {
    return path_join($base_dir, $requested_name);
}

class Directory_Helper_Good_Containment_Check {
    // ok: claude.php.wordpress.file.path-resolver-missing-containment-check
    public static function generate_user_filepath($form_id, $name, $filename) {
        $user_file_dir = static::generate_user_file_dirpath($form_id, $name);
        if (!$user_file_dir || !is_dir($user_file_dir)) {
            return false;
        }
        $normalized_filename = wp_normalize_path($filename);
        if (wp_basename($normalized_filename) !== $normalized_filename || strstr($normalized_filename, "\0")) {
            throw new \RuntimeException('Invalid file reference requested.');
        }
        $filepath = path_join($user_file_dir, $filename);
        $filepath = wp_normalize_path($filepath);
        $user_file_dir = trailingslashit(wp_normalize_path($user_file_dir));
        if (0 !== strpos($filepath, $user_file_dir)) {
            throw new \RuntimeException('Invalid file reference requested.');
        }
        return $filepath;
    }
}

class Directory_Helper_Bad_Unvalidated_Id_Join {
    // ruleid: claude.php.wordpress.file.path-resolver-missing-containment-check
    public static function generate_user_dirpath($form_id, $do_create_directory = true) {
        $saved_token = Csrf::saved_token();
        if (!preg_match('|^[a-z0-9]+$|', $saved_token)) {
            throw new \RuntimeException('Failed to generate user directory path.');
        }
        $user_dir = path_join(static::get(), $saved_token);
        $user_dir = path_join($user_dir, (string) $form_id);
        if ($do_create_directory && !wp_mkdir_p($user_dir)) {
            throw new \RuntimeException('Can\'t create user directory.');
        }
        return $user_dir;
    }
}

class Directory_Helper_Good_Id_Validated_Before_Join {
    // ok: claude.php.wordpress.file.path-resolver-missing-containment-check
    public static function generate_user_dirpath($form_id, $do_create_directory = true) {
        $saved_token = Csrf::saved_token();
        if (!Helper::is_valid_token_format($saved_token)) {
            throw new \RuntimeException('Failed to generate user directory path.');
        }
        $form_id = Helper::sanitize_form_id($form_id);
        if (false === $form_id) {
            throw new \RuntimeException('Invalid form ID.');
        }
        $user_dir = path_join(static::get(), $saved_token);
        $user_dir = path_join($user_dir, (string) $form_id);
        if ($do_create_directory && !wp_mkdir_p($user_dir)) {
            throw new \RuntimeException('Can\'t create user directory.');
        }
        return $user_dir;
    }
}
