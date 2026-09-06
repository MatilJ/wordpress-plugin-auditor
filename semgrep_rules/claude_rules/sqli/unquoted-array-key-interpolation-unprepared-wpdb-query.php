<?php
// Test cases for claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query

class ExampleUnquotedArrayKeySqli
{
    public function recordItem_vulnerable_array_key()
    {
        global $wpdb;
        $current_item = $this->get_current_item();
        // ruleid: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $exist = $wpdb->get_row("SELECT `item_id` FROM `wp_items` WHERE `date` = '" . current_time('Y-m-d') . "' AND `type` = '{$current_item['type']}' AND `id` = {$current_item['id']}", ARRAY_A);
        return $exist;
    }

    public function recordItem_vulnerable_object_property()
    {
        global $wpdb;
        $context = $this->get_context_object();
        // ruleid: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $rows = $wpdb->get_results("SELECT * FROM `wp_visits` WHERE `visitor_id` = {$context->visitor_id} AND `active` = 1");
        return $rows;
    }

    public function recordItem_patched_quoted_interpolation()
    {
        global $wpdb;
        $current_item = $this->get_current_item();
        // Same shape as the vulnerable case, but the value is now single-quoted
        // in the SQL text (the observable sink-side change from the real patch).
        // ok: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $exist = $wpdb->get_row("SELECT `item_id` FROM `wp_items` WHERE `date` = '" . current_time('Y-m-d') . "' AND `type` = '{$current_item['type']}' AND `id` = '{$current_item['id']}'", ARRAY_A);
        return $exist;
    }

    public function recordItem_safe_int_cast()
    {
        global $wpdb;
        $current_item = $this->get_current_item();
        $item_id = (int) $current_item['id'];
        // ok: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $exist = $wpdb->get_row("SELECT `item_id` FROM `wp_items` WHERE `type` = '" . esc_sql($current_item['type']) . "' AND `id` = " . $item_id, ARRAY_A);
        return $exist;
    }

    public function recordItem_safe_prepare()
    {
        global $wpdb;
        $current_item = $this->get_current_item();
        // ok: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $exist = $wpdb->get_row($wpdb->prepare("SELECT `item_id` FROM `wp_items` WHERE `type` = %s AND `id` = %d", $current_item['type'], $current_item['id']), ARRAY_A);
        return $exist;
    }

    public function get_users_with_wpdb_table_property()
    {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $rows = $wpdb->get_results("SELECT `user_id` FROM `wp_visitors` WHERE EXISTS (SELECT `ID` FROM `{$wpdb->users}` WHERE wp_visitors.user_id = {$wpdb->users}.ID)");
        return $rows;
    }

    private function get_current_item()
    {
        return array('type' => 'post', 'id' => 1);
    }

    private function get_context_object()
    {
        return (object) array('visitor_id' => 1);
    }

    // Branch B: '.'-concatenation form (the CWE-89 shape confirmed by a
    // second seeding CVE — an AJAX handler's request-array parameter
    // concatenated straight into a WHERE-clause numeric value).

    public function getBookings_vulnerable_concat_assign_then_sink($args)
    {
        global $wpdb;
        $extraCond = 'state = \'confirmed\'';
        // ruleid: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $query = 'SELECT * FROM ' . $wpdb->prefix . 'bookings WHERE calendar_id = ' . $args['calendar'] . ' AND ' . $extraCond;
        $bookings = $wpdb->get_results($query, ARRAY_A);
        return $bookings;
    }

    public function getBookings_vulnerable_concat_inline_sink($args)
    {
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $bookings = $wpdb->get_results('SELECT * FROM ' . $wpdb->prefix . 'bookings WHERE calendar_id = ' . $args['calendar']);
        return $bookings;
    }

    public function getBookings_patched_intval_cast($args)
    {
        global $wpdb;
        $extraCond = 'state = \'confirmed\'';
        // ok: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $query = 'SELECT * FROM ' . $wpdb->prefix . 'bookings WHERE calendar_id = ' . intval($args['calendar']) . ' AND ' . $extraCond;
        $bookings = $wpdb->get_results($query, ARRAY_A);
        return $bookings;
    }

    public function getBookings_safe_prepare_concat($args)
    {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.unquoted-array-key-interpolation-unprepared-wpdb-query
        $query = $wpdb->prepare('SELECT * FROM ' . $wpdb->prefix . 'bookings WHERE calendar_id = %d', $args['calendar']);
        $bookings = $wpdb->get_results($query);
        return $bookings;
    }
}
