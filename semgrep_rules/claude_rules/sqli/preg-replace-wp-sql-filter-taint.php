<?php
// preg-replace-wp-sql-filter-taint rule test cases

// ── VULNERABLE PATTERNS ──────────────────────────────────────────────────────

// Direct: $_POST flows into preg_replace replacement modifying $sql['where']
function um_vulnerable_where_direct($sql, $queries, $type, $primary_table, $primary_id_column, $context) {
    $search = sanitize_text_field($_POST['search']); // source: $_POST; sanitize_text_field is NOT a SQL sanitizer
    // ruleid: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
    $sql['where'] = preg_replace('/\bfoo\b/i', $search, $sql['where']);
    return $sql;
}

// Via intermediate variable: user input flows through a helper and into preg_replace replacement
function um_vulnerable_where_intermediate($sql, $queries, $type, $primary_table, $primary_id_column, $context) {
    global $wpdb;
    if ( ! empty( $_POST['search'] ) ) {
        $search      = sanitize_text_field( wp_unslash( $_POST['search'] ) ); // tainted
        $search_like = '%' . $wpdb->esc_like( $search ) . '%';                // still tainted (esc_like not a SQL sanitizer)
        // ruleid: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
        $sql['where'] = preg_replace( '/mt1\.meta_value = \'' . $search . '\'/im', $search_like . ' $1', $sql['where'], 1 );
    }
    return $sql;
}

// Tainted value in str_replace modifying $sql['join']
function um_vulnerable_join_str_replace($sql) {
    $value = $_GET['sort_key']; // source
    // ruleid: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
    $sql['join'] = str_replace('{{SORT_KEY}}', $value, $sql['join']);
    return $sql;
}

// Tainted value in preg_replace modifying $sql['having']
function um_vulnerable_having($sql) {
    $filter = $_REQUEST['filter']; // source
    // ruleid: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
    $sql['having'] = preg_replace('/PLACEHOLDER/', $filter, $sql['having']);
    return $sql;
}


// ── SAFE PATTERNS ────────────────────────────────────────────────────────────

// ok: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
// Safe: replacement goes through $wpdb->prepare() before preg_replace
function um_safe_prepare($sql) {
    global $wpdb;
    $search = sanitize_text_field( $_POST['search'] );
    $safe   = $wpdb->prepare( '%s', '%' . $wpdb->esc_like( $search ) . '%' );
    $sql['where'] = preg_replace( '/LIKE_PLACEHOLDER/', $safe, $sql['where'] );
    return $sql;
}

// ok: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
// Safe: replacement goes through esc_sql() before preg_replace
function um_safe_esc_sql($sql) {
    $search       = sanitize_text_field( $_POST['search'] );
    $escaped      = esc_sql( $search );
    $sql['where'] = preg_replace( '/PLACEHOLDER/', $escaped, $sql['where'] );
    return $sql;
}

// ok: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
// Safe: numeric cast eliminates all SQL metacharacters
function um_safe_intval($sql) {
    $page         = intval( $_POST['page'] );
    $sql['where'] = preg_replace( '/OFFSET_PLACEHOLDER/', $page, $sql['where'] );
    return $sql;
}

// ok: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
// Safe: replacement is a static string literal, not user input
function um_safe_literal($sql) {
    $sql['where'] = preg_replace( '/AND status = 1/', 'AND status = 0', $sql['where'] );
    return $sql;
}

// ok: claude.php.wordpress.sqli.preg-replace-wp-sql-filter-taint
// Not a SQL filter key — modifying $content is not a SQL context
function um_not_sql_context($content) {
    $search  = sanitize_text_field( $_POST['highlight'] );
    $content = preg_replace( '/(' . preg_quote( $search, '/' ) . ')/i', '<mark>$1</mark>', $content );
    return $content;
}
