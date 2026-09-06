<?php

class ConnectionDispatchExample
{
    public static function handle_static_call($submitted_lists, $service, $conversion_data)
    {
        $responses = [];

        // ruleid: claude.php.wordpress.access-control.foreach-selector-value-to-connection-sink-no-allowlist
        foreach ($submitted_lists as $list_item) {
            $responses[] = self::add_lead_to_connection(
                    $service,
                    $list_item,
                    $conversion_data
            );
        }

        return $responses;
    }

    public function handle_instance_call($submitted_lists, $service, $connector)
    {
        $responses = [];

        // ruleid: claude.php.wordpress.access-control.foreach-selector-value-to-connection-sink-no-allowlist
        foreach ($submitted_lists as $list_item) {
            $responses[] = $connector->subscribe_contact_to_list($service, $list_item);
        }

        return $responses;
    }

    // ok: claude.php.wordpress.access-control.foreach-selector-value-to-connection-sink-no-allowlist
    public static function handle_static_call_with_allowlist($submitted_lists, $allowed_lists, $service, $conversion_data)
    {
        $responses = [];

        foreach ($submitted_lists as $list_item) {
            if (in_array($list_item, $allowed_lists)) {
                $responses[] = self::add_lead_to_connection(
                        $service,
                        $list_item,
                        $conversion_data
                );
            }
        }

        return $responses;
    }

    // ok: claude.php.wordpress.access-control.foreach-selector-value-to-connection-sink-no-allowlist
    public function handle_instance_call_with_allowlist($submitted_lists, $allowed_lists, $service, $connector)
    {
        $responses = [];

        foreach ($submitted_lists as $list_item) {
            if (in_array($list_item, $allowed_lists)) {
                $responses[] = $connector->subscribe_contact_to_list($service, $list_item);
            }
        }

        return $responses;
    }

    // ok: claude.php.wordpress.access-control.foreach-selector-value-to-connection-sink-no-allowlist
    public static function unrelated_read_from_db($post_ids)
    {
        global $wpdb;

        $results = [];

        foreach ($post_ids as $post_id) {
            $results[] = $wpdb->get_row(
                $wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $post_id)
            );
        }

        return $results;
    }
}
