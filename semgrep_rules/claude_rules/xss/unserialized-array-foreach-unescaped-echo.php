<?php

// Test cases for claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo

// --- TRUE POSITIVES ---

function display_entry_tp1() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}entries WHERE id = 1");
    $entry = unserialize($row->entry_value);
    foreach ($entry as $key => $value) {
        // ruleid: claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo
        echo '<p><b>' . $key . '</b>: ' . $value . '</p>';
    }
}

function display_entry_file_branch_tp2() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}entries WHERE id = 1");
    $entry = unserialize($row->entry_value);
    foreach ($entry as $key => $data) {
        if (strpos($key, '_file') !== false) {
            // ruleid: claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo
            echo '<p><a href="' . $data . '">' . $data . '</a></p>';
        } else {
            $data = esc_html($data);
            echo '<p>' . $data . '</p>';
        }
    }
}

function display_entry_no_key_tp3() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT option_value FROM {$wpdb->prefix}options WHERE option_name = 'log'");
    $log = maybe_unserialize($row->option_value);
    foreach ($log as $line) {
        // ruleid: claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo
        echo '<li>' . $line . '</li>';
    }
}

// --- FALSE POSITIVES (properly sanitized / not attacker-influenced) ---

function display_entry_escaped_fp1() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}entries WHERE id = 1");
    $entry = unserialize($row->entry_value);
    foreach ($entry as $key => $value) {
        // ok: claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo
        echo '<p><b>' . esc_html($key) . '</b>: ' . esc_html($value) . '</p>';
    }
}

function display_entry_stripped_fp2() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}entries WHERE id = 1");
    $entry = unserialize($row->entry_value);
    foreach ($entry as $key => $data) {
        $data = sanitize_text_field($data);
        // ok: claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo
        echo '<p>' . $data . '</p>';
    }
}

function display_entry_json_fp3() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}entries WHERE id = 1");
    $entry = unserialize($row->entry_value);
    $out = array();
    foreach ($entry as $key => $value) {
        $out[$key] = $value;
    }
    // ok: claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo
    wp_send_json_success($out);
}

function display_entry_int_fp4() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}entries WHERE id = 1");
    $counts = unserialize($row->counts_value);
    foreach ($counts as $key => $value) {
        $value = absint($value);
        // ok: claude.php.wordpress.xss.unserialized-array-foreach-unescaped-echo
        echo '<span>' . $value . '</span>';
    }
}
