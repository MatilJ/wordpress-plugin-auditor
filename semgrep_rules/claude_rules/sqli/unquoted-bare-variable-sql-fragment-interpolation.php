<?php

function wfp_action_rest_payment_redirect($request) {
    $id = isset($request['id']) ? $request['id'] : 0;
    // ruleid: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
    $wrere = " AND donate_id = $id";
    $forms = self::instance()->wfp_get_result('', $wrere);
    return $forms;
}

function stripe_ajax_wfp_callback($request) {
    $entry_id = !empty($_REQUEST['entry_id']) ? $_REQUEST['entry_id'] : 0;
    // ruleid: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
    $wrere = " AND donate_id = $entry_id";
    global $wpdb;
    $forms = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}wdp_fundraising WHERE 1 = 1" . $wrere);
    return $forms;
}

function get_pending_orders_where($order_id) {
    $where = "";
    // ruleid: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
    $where .= " OR order_id = $order_id";
    return $where;
}

// ok: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
function wfp_action_rest_payment_redirect_fixed(\WP_REST_Request $request) {
    $id = isset($request['id']) ? intval($request['id']) : 0;
    global $wpdb;
    $forms = $wpdb->get_results($wpdb->prepare("SELECT * FROM " . $wpdb->prefix . "wdp_fundraising WHERE donate_id = %d", $id));
    return $forms;
}

// ok: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
function get_result_by_table($table_name, $where_clause) {
    global $wpdb;
    $myrows = $wpdb->get_results("SELECT * FROM `$table_name` WHERE 1 = 1 $where_clause");
    return $myrows;
}

// ok: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
function get_row_for_current_page($current_page) {
    $where = " AND `id` = '$current_page[id]'";
    return $where;
}

// ok: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
function get_wpdb_prefixed_condition() {
    global $wpdb;
    $where = " AND table_name = $wpdb->prefix";
    return $where;
}

// ok: claude.php.wordpress.sqli.unquoted-bare-variable-sql-fragment-interpolation
// Confirmed FP: kirki 6.1.1 includes/HelperFunctions.php:1904-1907 — $S binds
// to an entire closure literal (not a SQL-fragment string at all), whose own
// PHP source text ("$where .= $where_sql;") coincidentally satisfies the
// regex purely because "where" appears as a variable/parameter name.
function register_posts_where_filter($where_sql) {
    $callback = function ($where) use ($where_sql) {
        $where .= $where_sql;
        return $where;
    };
    add_filter('posts_where', $callback);
    return $callback;
}
