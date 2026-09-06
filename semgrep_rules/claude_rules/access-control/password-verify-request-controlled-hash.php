<?php
// Test cases for claude.php.wordpress.access-control.password-verify-request-controlled-hash

// ruleid: claude.php.wordpress.access-control.password-verify-request-controlled-hash
if (!password_verify($token_str, $_COOKIE['mf_cookie'])) {
    $status = false;
}

// ruleid: claude.php.wordpress.access-control.password-verify-request-controlled-hash
if (isset($_COOKIE['bWYtY29va2ll']) && !password_verify($token_str, sanitize_text_field(wp_unslash($_COOKIE['bWYtY29va2ll'])))) {
    $status = false;
}

// ok: claude.php.wordpress.access-control.password-verify-request-controlled-hash
$stored_token_hash = get_transient('transient_token_hash_' . $post_id);
$provided_token_hash = hash('sha256', sanitize_text_field(wp_unslash($_COOKIE['mf_cookie'])));
if (!hash_equals($stored_token_hash, $provided_token_hash)) {
    $status = false;
}

// ok: claude.php.wordpress.access-control.password-verify-request-controlled-hash
global $wpdb;
$user_row = $wpdb->get_row($wpdb->prepare("SELECT password_hash FROM {$wpdb->prefix}my_table WHERE id = %d", $user_id));
if (!password_verify($_POST['password'], $user_row->password_hash)) {
    wp_die('Invalid credentials');
}
