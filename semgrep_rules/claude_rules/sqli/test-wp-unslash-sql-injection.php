<?php
// Test file for claude.php.wordpress.sqli.wp-unslash-sql-injection

global $wpdb;

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.sqli.wp-unslash-sql-injection
$name = wp_unslash($_POST['name']);
$wpdb->query("SELECT * FROM {$wpdb->users} WHERE display_name = '$name'");

// ruleid: claude.php.wordpress.sqli.wp-unslash-sql-injection
$search = sanitize_text_field(wp_unslash($_GET['s']));
$wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE post_title LIKE '%$search%'");

// ruleid: claude.php.wordpress.sqli.wp-unslash-sql-injection
$question_sql = sanitize_text_field(wp_unslash($_COOKIE['question_ids']));
$wpdb->get_results("SELECT * FROM {$wpdb->prefix}questions WHERE question_id IN ($question_sql)");

// --- FALSE POSITIVES (ok) ---

// ok: claude.php.wordpress.sqli.wp-unslash-sql-injection
$name = wp_unslash($_POST['name']);
$wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->users} WHERE display_name = %s", $name));

// ok: claude.php.wordpress.sqli.wp-unslash-sql-injection
$id = intval(wp_unslash($_GET['id']));
$wpdb->query("SELECT * FROM {$wpdb->posts} WHERE ID = $id");

// ok: claude.php.wordpress.sqli.wp-unslash-sql-injection
$key = sanitize_key(wp_unslash($_POST['meta_key']));
$wpdb->get_var("SELECT meta_value FROM {$wpdb->postmeta} WHERE meta_key = '$key'");
