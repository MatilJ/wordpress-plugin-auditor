<?php
// Test file for claude.php.wordpress.sqli.sprintf-sql-build

global $wpdb;

// --- TRUE POSITIVES ---

// ruleid: claude.php.wordpress.sqli.sprintf-sql-build
$wpdb->query(sprintf("DELETE FROM %s WHERE id = %s", $table, $_GET['id']));

// ruleid: claude.php.wordpress.sqli.sprintf-sql-build
$wpdb->get_results(sprintf("SELECT * FROM %s WHERE name = '%s'", $wpdb->prefix . 'custom', $name));

// ruleid: claude.php.wordpress.sqli.sprintf-sql-build
$wpdb->get_var(sprintf("SELECT COUNT(*) FROM %s WHERE status = '%s'", $table_name, $status));

// --- FALSE POSITIVES (ok) ---

// ok: claude.php.wordpress.sqli.sprintf-sql-build
$wpdb->query($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id));

// ok: claude.php.wordpress.sqli.sprintf-sql-build
$message = sprintf("Found %d results for %s", $count, $search_term);

// ok: claude.php.wordpress.sqli.sprintf-sql-build
$wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title LIKE %s", '%' . $search . '%'));
