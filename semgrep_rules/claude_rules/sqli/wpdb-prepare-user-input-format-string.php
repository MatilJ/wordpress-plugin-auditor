<?php
/**
 * Test cases for wpdb-prepare-user-input-format-string.yaml
 * Rule id: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
 */

// TP: entire format string is user input
function tp_whole_format_string() {
    global $wpdb;
    $q = $_GET['q'];
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
    $wpdb->query( $wpdb->prepare( $q ) );
}

// TP: user input interpolated into the format string (table name), value uses %d
function tp_interpolated_table() {
    global $wpdb;
    $table = $_GET['table'];
    $id = (int) $_GET['id'];
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
    $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table WHERE id = %d", $id ) );
}

// TP: user input concatenated into the format string
function tp_concat_format_string() {
    global $wpdb;
    $col = $_POST['col'];
    // ruleid: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
    $wpdb->get_var( $wpdb->prepare( "SELECT " . $col . " FROM t WHERE id = %d", 1 ) );
}

// TP: wrapper prepare() with user input as format string
class Tp_WrapperPrepareFormat {
    private $wpdb;
    function run() {
        $sql = $_REQUEST['sql'];
        // ruleid: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
        $this->wpdb->get_results( $this->wpdb->prepare( $sql, 1 ) );
    }
}

// OK: constant format string, user input passed as a %-placeholder VALUE
function ok_value_arg() {
    global $wpdb;
    $id = $_GET['id'];
    // ok: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
    $wpdb->get_results( $wpdb->prepare( "SELECT * FROM t WHERE id = %d", $id ) );
}

// OK: constant format string, multiple user values as placeholders
function ok_multiple_values( $request ) {
    global $wpdb;
    $name = $request->get_param( 'name' );
    $email = $request->get_param( 'email' );
    // ok: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
    $wpdb->get_row( $wpdb->prepare( "SELECT * FROM u WHERE name = %s AND email = %s", $name, $email ) );
}

// OK: dynamic column reduced to a safe token before interpolation
function ok_sanitize_key_column() {
    global $wpdb;
    $col = sanitize_key( $_GET['col'] );
    $id = (int) $_GET['id'];
    // ok: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
    $wpdb->get_var( $wpdb->prepare( "SELECT $col FROM t WHERE id = %d", $id ) );
}

// OK: standard safe dynamic IN() — array_fill builds a "%d,%d,..." placeholder
// string; only the COUNT derives from input, never the data. (jeg-elementor-kit
// 3.1.1 class-api.php:505-513 was a confirmed FP of this shape.)
function ok_array_fill_placeholders() {
    global $wpdb;
    $includes = array_filter( explode( ',', $_GET['include'] ), 'is_numeric' );
    $placeholders = implode( ',', array_fill( 0, count( $includes ), '%d' ) );
    // ok: claude.php.wordpress.sqli.wpdb-prepare-user-input-format-string
    $wpdb->get_results( $wpdb->prepare( "SELECT ID FROM t WHERE ID IN ($placeholders)", $includes ) );
}
