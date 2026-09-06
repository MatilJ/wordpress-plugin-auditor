<?php

class Staging_Copy_Db_Ex_Test {

    public $new_prefix;
    public $old_prefix;

    public function create_table_direct_drop($table_name) {
        $new_table_name = $this->new_prefix . substr($table_name, strlen($this->old_prefix));
        $new_db = $this->get_db_instance(true);
        // ruleid: claude.php.wordpress.sqli.raw-table-identifier-concat-unprepared-query
        $new_db->query("DROP TABLE IF EXISTS {$new_table_name}");
    }

    public function rename_table_from_request($old_table) {
        $new_prefix = $_POST['table_prefix'];
        $new_table = $new_prefix . 'posts';
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.raw-table-identifier-concat-unprepared-query
        $wpdb->query("RENAME TABLE {$old_table} TO {$new_table}");
    }

    public function create_table_allowlisted($prefix) {
        if (!preg_match('/^[A-Za-z0-9_]+$/', $prefix)) {
            wp_die('invalid prefix');
        }
        global $wpdb;
        $sql = $wpdb->prepare("DROP TABLE IF EXISTS %i", $prefix . 'options');
        // ok: claude.php.wordpress.sqli.raw-table-identifier-concat-unprepared-query
        $wpdb->query($sql);
    }

    public function dbdelta_style_install() {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.raw-table-identifier-concat-unprepared-query
        $wpdb->query("CREATE TABLE {$wpdb->prefix}my_plugin_log (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, PRIMARY KEY (id))");
    }

    public function get_db_instance($is_new) {
        global $wpdb;
        return $wpdb;
    }
}
