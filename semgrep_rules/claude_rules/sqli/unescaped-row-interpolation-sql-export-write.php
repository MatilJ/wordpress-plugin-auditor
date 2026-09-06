<?php
// Test cases for claude.php.wordpress.sqli.unescaped-row-interpolation-sql-export-write

function export_items_vulnerable($stream, $wpdb)
{
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items;");
    $prefix = '';
    foreach ($rows as $item) {
        // ruleid: claude.php.wordpress.sqli.unescaped-row-interpolation-sql-export-write
        fwrite($stream, "{$prefix}({$item->id},\"{$item->label}\")");
        $prefix = ',';
    }
}

function export_logs_vulnerable($stream, $wpdb)
{
    $records = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}logs;");
    foreach ($records as $log) {
        // ruleid: claude.php.wordpress.sqli.unescaped-row-interpolation-sql-export-write
        fputs($stream, "({$log->id},'{$log->message}')");
    }
}

function export_notes_vulnerable_fprintf($stream, $wpdb)
{
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}notes;");
    foreach ($rows as $note) {
        // ruleid: claude.php.wordpress.sqli.unescaped-row-interpolation-sql-export-write
        fprintf($stream, "({$note->id},\"{$note->body}\")");
    }
}

function export_items_fixed($stream, $wpdb)
{
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items;");
    $prefix = '';
    foreach ($rows as $item) {
        // ok: claude.php.wordpress.sqli.unescaped-row-interpolation-sql-export-write
        fprintf($stream, "{$prefix}({$item->id},\"%s\")", esc_sql($item->label));
        $prefix = ',';
    }
}

function export_items_fixed_concat($stream, $wpdb)
{
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items;");
    foreach ($rows as $item) {
        // ok: claude.php.wordpress.sqli.unescaped-row-interpolation-sql-export-write
        fwrite($stream, "({$item->id},\"" . esc_sql($item->label) . "\")");
    }
}

function display_items_not_sql_export($wpdb)
{
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items;");
    foreach ($rows as $item) {
        // ok: claude.php.wordpress.sqli.unescaped-row-interpolation-sql-export-write
        echo esc_html($item->label);
    }
}
