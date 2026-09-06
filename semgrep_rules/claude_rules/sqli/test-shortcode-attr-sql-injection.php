<?php
// Test file for claude.php.wordpress.sqli.shortcode-attr-sql-injection

global $wpdb;

// --- TRUE POSITIVES ---

function my_shortcode_callback($atts) {
    global $wpdb;

    // ruleid: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    $wpdb->query("SELECT * FROM {$wpdb->posts} WHERE ID = " . $atts['id']);

    $orderby = $atts['orderby'];
    // ruleid: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    $wpdb->get_results("SELECT * FROM {$wpdb->posts} ORDER BY $orderby");

    // ruleid: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = '" . $atts['type'] . "'");
}

function my_widget_render($instance) {
    global $wpdb;

    $limit = $instance['count'];
    // ruleid: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    $wpdb->get_results("SELECT * FROM {$wpdb->posts} LIMIT $limit");
}

// --- FALSE POSITIVES (ok) ---

function safe_shortcode($atts) {
    global $wpdb;

    // ok: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $atts['id']));

    // ok: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    $id = intval($atts['id']);
    $wpdb->query("SELECT * FROM {$wpdb->posts} WHERE ID = $id");

    // ok: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    $key = sanitize_key($atts['meta_key']);
    $wpdb->get_var("SELECT meta_value FROM {$wpdb->postmeta} WHERE meta_key = '$key'");
}

class Payments_Table {
    // ok: claude.php.wordpress.sqli.shortcode-attr-sql-injection
    // $instance here is a Singleton accessor result (an object), not a WP_Widget
    // config array — must not be treated as a shortcode/widget-attribute source.
    public static function get_all_main_payments($args = []) {
        global $wpdb;
        $instance   = self::get_instance();
        $table_name = $instance->get_tablename();
        return $wpdb->get_results("SELECT * FROM {$table_name}");
    }
}
