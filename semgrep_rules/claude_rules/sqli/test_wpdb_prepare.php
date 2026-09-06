<?php
// Tests for claude.php.wordpress.sqli.wpdb-prepare-concatenation

// --- TRUE POSITIVES: user-controlled variable concatenated into format string ---

function vuln_user_var_prefix() {
    global $wpdb;
    $table = $_POST['table'];
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( $table . ' WHERE id = %d', 1 );
}

function vuln_user_var_suffix() {
    global $wpdb;
    $col = $_GET['col'];
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( 'SELECT * FROM posts WHERE ' . $col . ' = %s', 'value' );
}

// NOTE: indirect sprintf (fmt assigned to variable first) is a known
// search-mode limitation — taint mode would be required to catch it.
function vuln_sprintf_direct() {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( sprintf( 'SELECT * FROM %s WHERE id = %%d', $_GET['tbl'] ), 1 );
}

// --- FALSE POSITIVES: safe concatenation patterns ---

// Core WP table properties ($wpdb->posts, $wpdb->options, etc.)
function safe_wpdb_core_table() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( 'SELECT * FROM ' . $wpdb->posts . ' WHERE ID = %d', 1 );
}

function safe_wpdb_prefix() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( 'DELETE FROM ' . $wpdb->prefix . 'custom_table WHERE id = %d', 5 );
}

// PHP constants (ALL_CAPS) — defined via define(), not user input
function safe_constant_prefix() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( MY_TABLE_CONSTANT . ' WHERE id = %d', 1 );
}

// self::$table_* static class properties — plugin-defined table names
class MyPlugin {
    static $table_orders = '';
    static $table_items  = '';
    static $table_rates  = '';

    public static function safe_self_prefix() {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
        $wpdb->prepare( 'DELETE FROM ' . self::$table_orders . ' WHERE id = %d', 1 );
    }

    public static function safe_self_suffix() {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
        $wpdb->prepare( 'SELECT id FROM ' . self::$table_items . ' WHERE type = %s', 'foo' );
    }

    public static function safe_self_middle() {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
        $wpdb->prepare(
            'SELECT * FROM ' . self::$table_rates . ' r INNER JOIN other o ON r.id = o.rate_id WHERE r.id = %d',
            42
        );
    }

    // static:: property (late static binding)
    public static function safe_static_property() {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
        $wpdb->prepare( 'DELETE FROM ' . static::$table_orders . ' WHERE rule_id = %d', 5 );
    }
}

// $this->table_name instance property (also commonly a class-held table name)
class PluginTwo {
    public $table_name = '';

    public function safe_this_table() {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
        $wpdb->prepare( 'SELECT * FROM ' . $this->table_name . ' WHERE id = %d', 1 );
    }
}

// Concrete class name (e.g., BABE_Prices::$table_discount) — same pattern as self::
class BABE_Prices {
    public static $table_discount = '';
    public static $table_rate = '';
}

function safe_concrete_class_table_prop() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( 'DELETE FROM ' . BABE_Prices::$table_discount . ' WHERE booking_obj_id = %d', 1 );
}

function safe_concrete_class_table_rate_prefix() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.wpdb-prepare-concatenation
    $wpdb->prepare( 'DELETE FROM ' . BABE_Prices::$table_rate . ' WHERE rate_id = %d', 1 );
}
