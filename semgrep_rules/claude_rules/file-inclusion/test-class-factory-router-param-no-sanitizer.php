<?php
// Test file for lfi class-factory-router-param-no-sanitizer rule

class Request_Helper {
    static function get_var($name) {
        return isset($_REQUEST[$name]) ? $_REQUEST[$name] : null;
    }
}

class Module_Loader {
    static function get_model($name) {
        $file_path = MODEL_DIR . $name . '/model.php';
        include_once $file_path;
        $classname = "Model_" . $name;
        return new $classname();
    }
}

class Ajax_Router {
    function handle() {
        $task = 'run';
        $module = Request_Helper::get_var('mod');
        // ruleid: claude.php.wordpress.lfi.class-factory-router-param-no-sanitizer
        $result = Module_Loader::get_model($module)->$task();
        echo $result;
    }

    function handle_unfixed_traversal_only() {
        $task = 'run';
        $module = Request_Helper::get_var('mod');
        // Real-world (weak) fix shape: only ".." is stripped, "/" is left
        // in place — still traversal-capable, so this must still flag.
        $module = str_replace("..", "", $module);
        // ruleid: claude.php.wordpress.lfi.class-factory-router-param-no-sanitizer
        $result = Module_Loader::get_model($module)->$task();
        echo $result;
    }

    function handle_fixed() {
        $task = 'run';
        $module = Request_Helper::get_var('mod');
        $module = str_replace("..", "", $module);
        $module = str_replace("/", "", $module);
        // ok: claude.php.wordpress.lfi.class-factory-router-param-no-sanitizer
        $result = Module_Loader::get_model($module)->$task();
        echo $result;
    }

    function handle_allowlisted() {
        $task = 'run';
        $module = Request_Helper::get_var('mod');
        $allowed = array('ticket', 'agent', 'reports');
        $module = in_array($module, $allowed, true) ? $module : 'ticket';
        // ok: claude.php.wordpress.lfi.class-factory-router-param-no-sanitizer
        $result = Module_Loader::get_model($module)->$task();
        echo $result;
    }
}

class Good_Db_Read_Report_Loader {
    public function get_report_module($report_id) {
        $report_id = absint($report_id);
        global $wpdb;
        // ok: claude.php.wordpress.lfi.class-factory-router-param-no-sanitizer
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}reports WHERE id = %d", $report_id));
    }
}
