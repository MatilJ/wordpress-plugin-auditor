<?php
// Test file for claude.php.wordpress.sqli.esc-attr-as-sql-sanitizer

global $wpdb;

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.sqli.esc-attr-as-sql-sanitizer
$wpdb->query("SELECT * FROM {$wpdb->posts} WHERE post_title = '" . esc_attr($title) . "'");

// ruleid: claude.php.wordpress.sqli.esc-attr-as-sql-sanitizer
$wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE ID = " . esc_attr($_GET['id']));

// ruleid: claude.php.wordpress.sqli.esc-attr-as-sql-sanitizer
$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = '" . esc_attr($status) . "'");

// --- FALSE POSITIVES (ok) ---

// ok: claude.php.wordpress.sqli.esc-attr-as-sql-sanitizer
$wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = %s", esc_attr($title));

// ok: claude.php.wordpress.sqli.esc-attr-as-sql-sanitizer
echo '<input value="' . esc_attr($value) . '">';

// ok: claude.php.wordpress.sqli.esc-attr-as-sql-sanitizer
$wpdb->query($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id));
