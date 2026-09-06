<?php
// Test file for claude.php.wordpress.sqli.esc-url-raw-as-sql-sanitizer

global $wpdb;

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.sqli.esc-url-raw-as-sql-sanitizer
$wpdb->query("SELECT * FROM {$wpdb->postmeta} WHERE meta_value = '" . esc_url_raw($url) . "'");

// ruleid: claude.php.wordpress.sqli.esc-url-raw-as-sql-sanitizer
$wpdb->get_results("SELECT * FROM {$wpdb->options} WHERE option_value = '" . esc_url_raw($_POST['redirect_url']) . "'");

// ruleid: claude.php.wordpress.sqli.esc-url-raw-as-sql-sanitizer
$wpdb->get_var("SELECT option_id FROM {$wpdb->options} WHERE option_value = '" . esc_url_raw($callback_url) . "'");

// --- FALSE POSITIVES (ok) ---

// ok: claude.php.wordpress.sqli.esc-url-raw-as-sql-sanitizer
$wpdb->prepare("SELECT * FROM {$wpdb->postmeta} WHERE meta_value = %s", esc_url_raw($url));

// ok: claude.php.wordpress.sqli.esc-url-raw-as-sql-sanitizer
update_option('redirect_url', esc_url_raw($url));

// ok: claude.php.wordpress.sqli.esc-url-raw-as-sql-sanitizer
$wpdb->query($wpdb->prepare("SELECT * FROM {$wpdb->options} WHERE option_value = %s", $safe_val));
