<?php
// Test file for claude.php.wordpress.file-inclusion.superglobal-selector-var-to-include-no-containment-check

class Admin_Page_Vulnerable {

    // Real pre-fix shape: ternary-from-$_GET assigned to a local var, then
    // interpolated into a require path with no containment check.
    function render_page() {
        $tab = isset( $_GET['tab'] ) ? $_GET['tab'] : 'settings';
        // ruleid: claude.php.wordpress.file-inclusion.superglobal-selector-var-to-include-no-containment-check
        require dirname(__FILE__) . "/admin-partials/{$tab}.php";
    }
}

class Admin_Page_Vulnerable_Concat {

    // Same idiom via $_REQUEST + null-coalescing, plain concatenation sink.
    function render() {
        $section = $_REQUEST['section'] ?? 'main';
        // ruleid: claude.php.wordpress.file-inclusion.superglobal-selector-var-to-include-no-containment-check
        include ABSPATH . 'views/' . $section . '.php';
    }
}

class Admin_Page_Fixed_Realpath {

    // Official fix shape: realpath() containment check guards the require.
    function render_page() {
        $tab = isset( $_GET['tab'] ) ? $_GET['tab'] : 'settings';
        $dir = trailingslashit( dirname(__FILE__) ) . 'admin-partials/';
        $file = $dir . $tab . '.php';
        if ( file_exists( $file ) && strpos( realpath( $file ), realpath( $dir ) ) === 0 ) {
            // ok: claude.php.wordpress.file-inclusion.superglobal-selector-var-to-include-no-containment-check
            require $file;
        } else {
            wp_die( 'Invalid tab' );
        }
    }
}

class Admin_Page_Fixed_Allowlist {

    // Fixed via an early allow-list guard clause.
    function render_page() {
        $tab = isset( $_GET['tab'] ) ? $_GET['tab'] : 'settings';
        if ( ! in_array( $tab, array( 'settings', 'tools', 'logs' ), true ) ) {
            wp_die( 'Invalid tab' );
        }
        // ok: claude.php.wordpress.file-inclusion.superglobal-selector-var-to-include-no-containment-check
        require dirname(__FILE__) . "/admin-partials/{$tab}.php";
    }
}

class Admin_Page_DB_Read {

    // Unrelated WP DB-read pattern in the same shaped class — no include/require at all.
    function get_log_row( $id ) {
        global $wpdb;
        $id = absint( $id );
        // ok: claude.php.wordpress.file-inclusion.superglobal-selector-var-to-include-no-containment-check
        return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}logs WHERE id = %d", $id ) );
    }
}
