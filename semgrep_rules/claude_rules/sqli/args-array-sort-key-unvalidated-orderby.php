<?php
/**
 * Test file for claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
 *
 * A DB-helper function reads 'sort'/'orderby'/'order_by' straight out of its
 * own $args parameter and reaches a raw $wpdb query, without re-validating
 * the whole args array first (trusted-by-convention query-args parameter).
 */

// --- TRUE POSITIVES ---

// TP-1: bare array-key read, no validation at all, straight into ORDER BY.
class TP1_DB {
    public static function get_items( $args = array() ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $sort = $args['sort'];
        $order_sql = empty( $sort ) ? '' : 'ORDER BY ' . esc_sql( $sort );
        $wpdb->query( "SELECT * FROM {$wpdb->prefix}items $order_sql" );
    }
}

// TP-2: ternary-style read (isset), matching the real-world shape.
class TP2_DB {
    public static function get_locations( $query_args = array() ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $sort = isset( $query_args['sort'] ) ? $query_args['sort'] : '';
        $sort_sql = empty( $sort ) ? '' : 'ORDER BY ' . esc_sql( $sort );
        return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}locations $sort_sql" );
    }
}

// TP-3: 'orderby' key name variant.
class TP3_DB {
    public static function get_rows( $args ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $orderby = $args['orderby'];
        return $wpdb->get_col( "SELECT id FROM {$wpdb->prefix}rows ORDER BY $orderby" );
    }
}

// TP-4: 'orderby' key, isset()-ternary read shape (CVE-2026-5073 real-world shape —
// a directory/listing DB-helper reading 'orderby' out of its own $opts array with a
// default fallback, no allow-list, straight into an unprepared ORDER BY concatenation).
class TP4_DB {
    function get_directory_members( $tempData, $opts = array() ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $orderby = isset( $opts['orderby'] ) ? $opts['orderby'] : 'user_registered';
        $order_by_keyword = "u.{$orderby}";
        $order_by = ' ORDER BY ' . $order_by_keyword;
        return $wpdb->get_results( "SELECT u.ID FROM {$wpdb->users} u" . $order_by );
    }
}

// TP-5: 'order_by' key, empty()-ternary read shape.
class TP5_DB {
    public static function query_items( $args = array() ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $order_by = empty( $args['order_by'] ) ? 'id' : $args['order_by'];
        return $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}items ORDER BY $order_by" );
    }
}

// --- FALSE POSITIVES (OK) ---

// OK-1: the fix shape — whole-args array revalidated through a sanitize-
// style wrapper before the 'sort' key is read out of it.
class OK1_DB {
    private static function sanitize_query_args( $args ) {
        // pretend allow-list validation of every key, including 'sort'
        return $args;
    }

    public static function get_items( $args = array() ) {
        global $wpdb;
        $args = self::sanitize_query_args( $args );
        // ok: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $sort = isset( $args['sort'] ) ? $args['sort'] : '';
        $order_sql = empty( $sort ) ? '' : 'ORDER BY ' . esc_sql( $sort );
        $wpdb->query( "SELECT * FROM {$wpdb->prefix}items $order_sql" );
    }
}

// OK-1b: same whole-array sanitize-wrapper fix shape, but for the 'orderby'
// isset()-ternary read added in the CVE-2026-5073 extension — confirms the
// existing FP guard still applies to the newly-added pattern branches.
class OK1b_DB {
    private static function sanitize_query_args( $opts ) {
        return $opts;
    }

    function get_directory_members( $tempData, $opts = array() ) {
        global $wpdb;
        $opts = self::sanitize_query_args( $opts );
        // ok: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $orderby = isset( $opts['orderby'] ) ? $opts['orderby'] : 'user_registered';
        $order_by = ' ORDER BY u.' . $orderby;
        return $wpdb->get_results( "SELECT u.ID FROM {$wpdb->users} u" . $order_by );
    }
}

// OK-2: no raw $wpdb sink in the function at all (e.g. template/localize use).
class OK2_Template {
    public static function localize( $args = array() ) {
        // ok: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $sort = isset( $args['sort'] ) ? $args['sort'] : '';
        wp_localize_script( 'my-handle', 'myData', array( 'sort' => $sort ) );
    }
}

// OK-3: the function only builds a parameterized statement via prepare() and
// never itself calls a raw execution method (query/get_results/get_row/
// get_var/get_col) — the caller is responsible for executing it.
class OK3_DB {
    public static function build_query( $args = array() ) {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.args-array-sort-key-unvalidated-orderby
        $sort = isset( $args['sort'] ) ? $args['sort'] : 'id';
        return $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items ORDER BY %i", $sort );
    }
}
