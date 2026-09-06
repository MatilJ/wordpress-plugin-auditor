<?php
/**
 * Test cases for wpdb-wrapper-property-user-input-taint.yaml
 * Rule id: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
 */

// TP: $this->wpdb-> alias, raw WHERE
class Tp_ThisWpdb {
    private $wpdb;
    function __construct() { global $wpdb; $this->wpdb = $wpdb; }
    function run() {
        $id = $_POST['id'];
        // ruleid: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
        $this->wpdb->get_results( "SELECT * FROM t WHERE id = '$id'" );
    }
}

// TP: $this->db-> alias, raw ORDER BY
class Tp_ThisDb {
    private $db;
    function run() {
        $order = $_GET['order'];
        // ruleid: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
        $this->db->get_var( "SELECT id FROM t ORDER BY $order" );
    }
}

// TP: $GLOBALS['wpdb'] access
function tp_globals_wpdb() {
    $name = $_REQUEST['name'];
    // ruleid: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
    $GLOBALS['wpdb']->get_row( "SELECT * FROM users WHERE login = '$name'" );
}

// TP: object-variable wrapper ($obj->db->), REST param
function tp_obj_db_rest( $service, $request ) {
    $term = $request->get_param( 'term' );
    // ruleid: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
    $service->db->get_col( "SELECT name FROM items WHERE label LIKE '%$term%'" );
}

// TP: $this->database-> alias, query()
class Tp_ThisDatabase {
    private $database;
    function run() {
        $cat = $_GET['cat'];
        // ruleid: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
        $this->database->query( "DELETE FROM cats WHERE slug = '$cat'" );
    }
}

// OK: parameterized through the wrapper's prepare()
class Ok_WrapperPrepare {
    private $wpdb;
    function run() {
        $id = $_POST['id'];
        // ok: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
        $this->wpdb->get_results( $this->wpdb->prepare( "SELECT * FROM t WHERE id = %d", $id ) );
    }
}

// OK: integer cast before the wrapper sink
class Ok_WrapperIntval {
    private $db;
    function run() {
        $id = intval( $_GET['id'] );
        // ok: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
        $this->db->get_var( "SELECT name FROM t WHERE id = $id" );
    }
}

// OK: sanitize_sql_orderby allowlist before the wrapper sink
class Ok_WrapperOrderby {
    private $wpdb;
    function run() {
        $orderby = sanitize_sql_orderby( $_GET['orderby'] );
        // ok: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
        $this->wpdb->get_results( "SELECT * FROM t ORDER BY $orderby" );
    }
}

// OK: no user input — internal/static value
class Ok_NoUserInput {
    private $wpdb;
    function run( $internal_id ) {
        // ok: claude.php.wordpress.sqli.wpdb-wrapper-property-user-input-taint
        $this->wpdb->get_row( "SELECT * FROM t WHERE id = $internal_id" );
    }
}
