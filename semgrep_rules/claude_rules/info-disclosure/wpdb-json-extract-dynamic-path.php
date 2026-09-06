<?php

class Entries_Table {

    // TP: two-step assignment — JSON path built via concatenation with a
    // caller-supplied field key, bound into a JSON_UNQUOTE/JSON_EXTRACT query.
    // Mirrors the confirmed SureForms Entries::has_duplicate_field_value() pattern.
    public function has_duplicate_field_value( $form_id, $field_key, $field_value ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'srfm_entries';
        // ruleid: claude.php.wordpress.info-disclosure.wpdb-json-extract-dynamic-path
        $json_path  = '$."' . $field_key . '"';
        $exists     = $wpdb->get_var( $wpdb->prepare(
            "SELECT 1 FROM {$table_name} WHERE form_id = %d AND status != 'trash'
             AND JSON_UNQUOTE(JSON_EXTRACT(form_data, %s)) = %s LIMIT 1",
            $form_id, $json_path, $field_value
        ) );
        return null !== $exists;
    }

    // TP: inline concatenation passed directly as the bind argument, single-quote wrapper.
    public function field_value_exists( $entry_table, $key, $value ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.info-disclosure.wpdb-json-extract-dynamic-path
        return (bool) $wpdb->get_var( $wpdb->prepare(
            "SELECT 1 FROM {$entry_table} WHERE JSON_EXTRACT(meta_json, %s) = %s LIMIT 1",
            '$.' . $key, $value
        ) );
    }

    // OK: JSON path is a hardcoded literal — no runtime variable in the path segment at all.
    // ok: claude.php.wordpress.info-disclosure.wpdb-json-extract-dynamic-path
    public function get_status_field( $entry_table, $entry_id ) {
        global $wpdb;
        return $wpdb->get_var( $wpdb->prepare(
            "SELECT JSON_UNQUOTE(JSON_EXTRACT(meta_json, '$.status')) FROM {$entry_table} WHERE id = %d",
            $entry_id
        ) );
    }

    // OK: dynamic value bound as a normal WHERE parameter, but the query performs
    // no JSON_EXTRACT/JSON_UNQUOTE at all — ordinary parameterized lookup.
    // ok: claude.php.wordpress.info-disclosure.wpdb-json-extract-dynamic-path
    public function get_entry_by_status( $entry_table, $status ) {
        global $wpdb;
        return $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$entry_table} WHERE status = %s LIMIT 1",
            $status
        ) );
    }
}
