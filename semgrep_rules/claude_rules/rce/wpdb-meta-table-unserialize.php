<?php

// ---- TRUE POSITIVES ----

function tp_custom_meta_table_foreach() {
    global $wpdb;
    $rows = $wpdb->get_results("SELECT meta_key, meta_value FROM {$wpdb->prefix}plugin_bookings_meta WHERE booking_id = 1", ARRAY_A);
    foreach ($rows as $row) {
        // ruleid: claude.php.wordpress.rce.wpdb-meta-table-unserialize
        $value = maybe_unserialize($row['meta_value']);
    }
}

function tp_custom_meta_table_option_value() {
    global $wpdb;
    $row = $wpdb->get_row($wpdb->prepare("SELECT option_value FROM {$wpdb->prefix}plugin_settings_meta WHERE id = %d", $id), ARRAY_A);
    // ruleid: claude.php.wordpress.rce.wpdb-meta-table-unserialize
    $settings = unserialize($row['option_value']);
    return $settings;
}

function tp_custom_meta_table_prefixed_key() {
    global $wpdb;
    $rows = $wpdb->get_results("SELECT id, field_value FROM {$wpdb->prefix}plugin_queue", ARRAY_A);
    foreach ($rows as $entry) {
        // ruleid: claude.php.wordpress.rce.wpdb-meta-table-unserialize
        $payload = maybe_unserialize($entry['field_value']);
    }
}

function tp_dynamic_field_suffix_key() {
    foreach ($leads as $lead_row) {
        $row = !empty($lead_row['detail']) ? $lead_row['detail'] : array();
        foreach ($fields as $k => $field) {
            // ruleid: claude.php.wordpress.rce.wpdb-meta-table-unserialize
            $val = maybe_unserialize($row[$field['name'] . '_field']);
        }
    }
}

// ---- SAFE VARIANTS ----

function ok_wrapper_method_scoped_call() {
    global $wpdb;
    $rows = $wpdb->get_results("SELECT meta_key, meta_value FROM {$wpdb->prefix}plugin_bookings_meta WHERE booking_id = 1", ARRAY_A);
    foreach ($rows as $row) {
        // ok: claude.php.wordpress.rce.wpdb-meta-table-unserialize
        $value = self::maybe_unserialize($row['meta_value']);
    }
}

function ok_class_scoped_dynamic_field_suffix_key() {
    foreach ($leads as $lead_row) {
        $row = !empty($lead_row['detail']) ? $lead_row['detail'] : array();
        foreach ($fields as $k => $field) {
            // ok: claude.php.wordpress.rce.wpdb-meta-table-unserialize
            $val = vxcf_form::maybe_unserialize($row[$field['name'] . '_field']);
        }
    }
}

function ok_allowed_classes_restricted() {
    global $wpdb;
    $row = $wpdb->get_row($wpdb->prepare("SELECT option_value FROM {$wpdb->prefix}plugin_settings_meta WHERE id = %d", $id), ARRAY_A);
    // ok: claude.php.wordpress.rce.wpdb-meta-table-unserialize
    $settings = unserialize($row['option_value'], array('allowed_classes' => false));
    return $settings;
}

function ok_wp_core_post_meta_read() {
    // ok: claude.php.wordpress.rce.wpdb-meta-table-unserialize
    $settings = maybe_unserialize(get_post_meta($post_id, 'plugin_settings', true));
    return $settings;
}

function ok_unrelated_array_key() {
    global $wpdb;
    $row = $wpdb->get_row("SELECT id, status FROM {$wpdb->prefix}plugin_log", ARRAY_A);
    // ok: claude.php.wordpress.rce.wpdb-meta-table-unserialize
    $value = maybe_unserialize($row['status']);
}
