<?php

// Test cases for claude.php.wordpress.access-control.wpdb-mass-table-drop-entrypoint-no-auth

class Demo_DB_Cleanup {
    private $all_tables;

    // ruleid: claude.php.wordpress.access-control.wpdb-mass-table-drop-entrypoint-no-auth
    public function bulk_reset(array $tables) {
        if (in_array('users', $tables)) {
            $this->reset_users = true;
        }

        $this->validate($tables);
        $this->rebuild();
    }

    private function drop_all_tables() {
        global $wpdb;
        foreach ($this->all_tables as $table) {
            $wpdb->query("DROP TABLE {$table}");
        }
    }
}

class Demo_Site_Wiper {
    private $rows_targets;

    // ruleid: claude.php.wordpress.access-control.wpdb-mass-table-drop-entrypoint-no-auth
    public function purge(array $selected_tables) {
        $this->prepare($selected_tables);
        $this->wipe_rows();
    }

    private function wipe_rows() {
        global $wpdb;
        foreach ($this->rows_targets as $t) {
            $wpdb->query("TRUNCATE TABLE {$t}");
        }
    }
}

class Demo_DB_Cleanup_Fixed {
    private $all_tables;

    // ok: claude.php.wordpress.access-control.wpdb-mass-table-drop-entrypoint-no-auth
    public function bulk_reset(array $tables) {
        if (wp_verify_nonce(@$_REQUEST['submit_reset_form'], 'reset_nonce') && current_user_can('administrator')) {
            $this->validate($tables);
            $this->rebuild();
        } else {
            throw new Exception('Please reload the page and try again.');
        }
    }

    private function drop_all_tables() {
        global $wpdb;
        foreach ($this->all_tables as $table) {
            $wpdb->query("DROP TABLE {$table}");
        }
    }
}

class Demo_Report_Reader {
    private $wanted_ids;

    // ok: claude.php.wordpress.access-control.wpdb-mass-table-drop-entrypoint-no-auth
    public function summarize(array $ids) {
        return $this->fetch_rows($ids);
    }

    private function fetch_rows() {
        global $wpdb;
        $rows = array();
        foreach ($this->wanted_ids as $id) {
            $rows[] = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$this->table} WHERE id = %d", $id));
        }
        return $rows;
    }
}
