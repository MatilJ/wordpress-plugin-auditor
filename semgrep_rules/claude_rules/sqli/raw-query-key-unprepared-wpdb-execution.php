<?php
// Test cases for claude.php.wordpress.sqli.raw-query-key-unprepared-wpdb-execution

function get_single_sql_result(array $options = array()) {
    $options += array('query' => null);
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.raw-query-key-unprepared-wpdb-execution
    return $wpdb->get_var($options['query']);
}

function get_sql_result(array $options = array()) {
    $options += array('query' => null);
    // ruleid: claude.php.wordpress.sqli.raw-query-key-unprepared-wpdb-execution
    return $this->container->getWordPressContext()->getDb()->get_results($options['query']);
}

function run_raw_sql($params) {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.raw-query-key-unprepared-wpdb-execution
    return $wpdb->query($params['sql']);
}

function get_post_by_id($post_id) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.raw-query-key-unprepared-wpdb-execution
    return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $post_id));
}

function get_option_value($settings) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.raw-query-key-unprepared-wpdb-execution
    return $wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $settings['option_name']));
}

function get_report_config($config) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.raw-query-key-unprepared-wpdb-execution
    return $wpdb->get_results($config['report_id']);
}
