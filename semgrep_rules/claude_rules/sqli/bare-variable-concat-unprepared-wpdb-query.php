<?php
// Test cases for claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query

function get_records_by_stored_value( $stored_value ) {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query = "SELECT id FROM " . $wpdb->prefix . "records m
            JOIN " . $wpdb->prefix . "posts p ON p.id = m.post_id
            WHERE m.meta_value = '" . $stored_value . "'
            AND p.post_type = 'record_sub'";
    $rows = $wpdb->get_results( $query );
    return $rows;
}

function get_row_inline( $requester_email ) {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    return $wpdb->get_var( "SELECT id FROM " . $wpdb->prefix . "log WHERE email = '" . $requester_email . "'" );
}

function get_records_by_stored_value_fixed( $stored_value ) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query = $wpdb->prepare( "SELECT id FROM {$wpdb->prefix}records m
            JOIN {$wpdb->prefix}posts p ON p.id = m.post_id
            WHERE m.meta_value = %s
            AND p.post_type = 'record_sub'",
        $stored_value );
    $rows = $wpdb->get_results( $query );
    return $rows;
}

function get_records_by_stored_value_escaped( $stored_value ) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query = "SELECT id FROM " . $wpdb->prefix . "records WHERE data = '" . esc_sql( $stored_value ) . "'";
    $rows = $wpdb->get_results( $query );
    return $rows;
}

// Trailing-variable variant (no $AFTER) — the tainted value is the LAST
// element of the '.' concat chain with nothing following it. This is the
// exact shape of the seeding CVE (an id parameter concatenated straight
// onto the end of a raw WHERE clause, no prepare()).
function get_affiliate_by_id( $affiliate_id ) {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $db_fields = $wpdb->get_results( 'SELECT * FROM ' . $wpdb->prefix . 'wpam_affiliates where affiliateId =' . $affiliate_id, ARRAY_A );
    return array_shift( $db_fields );
}

function get_row_by_id_inline( $user_id ) {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    return $wpdb->get_var( 'SELECT id FROM ' . $wpdb->prefix . 'log WHERE user_id =' . $user_id );
}

function get_affiliate_by_id_fixed( $affiliate_id ) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query = 'SELECT * FROM ' . $wpdb->prefix . 'wpam_affiliates where affiliateId = %s';
    $db_fields = $wpdb->get_results( $wpdb->prepare( $query, $affiliate_id ), ARRAY_A );
    return array_shift( $db_fields );
}

// Prepare-then-execute idiom: the concat-built skeleton is reassigned
// through $wpdb->prepare() BEFORE the final sink call — the sink actually
// receives prepare()'s escaped output, not the raw concatenation. Confirmed
// FP: shortpixel-image-optimiser 6.5.5 Queue.php's start/end-id lookups.
function get_start_id_prepared_between_concat_and_sink( $base_query, $date_field, $prepare_args ) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $startSQL = $base_query . '  ORDER BY ' . $date_field . ' DESC LIMIT 1';
    $startSQL = $wpdb->prepare( $startSQL, $prepare_args );
    $start_id = $wpdb->get_var( $startSQL );
    return $start_id;
}

// Same idiom, trailing-variable (no $AFTER) concat shape.
function get_row_by_id_prepared_between_concat_and_sink( $table_name, $id_placeholder ) {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $sql = 'SELECT * FROM ' . $table_name;
    $sql = $wpdb->prepare( $sql, $id_placeholder );
    $res = $wpdb->get_row( $sql );
    return $res;
}

// Hardcoded table-name idiom: $table_name is assigned earlier in the same
// function to $wpdb->prefix concatenated with only a string literal, then
// used as the bare $VAR in the DROP TABLE concat. Neither operand is
// attacker-influenceable regardless of the missing prepare()/esc_sql().
function drop_plugin_table_double_quoted() {
    global $wpdb;
    $table_name = $wpdb->prefix . "asenha_failed_logins";
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $wpdb->query( "DROP TABLE IF EXISTS `" . $table_name . "`" );
}

function drop_plugin_table_single_quoted() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'asenha_failed_logins';
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $wpdb->query( 'DROP TABLE IF EXISTS `' . $table_name . '`' );
}

// Bare PHP constant (define()'d, ALL_CAPS) concatenated directly — a
// compile-time literal with no attacker influence, distinguishable from a
// tainted variable because a constant reference has no leading '$' sigil.
define( 'PLUGIN_CPT', 'plugin_videos' );
function clear_plugin_posts() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $ids = $wpdb->get_col( "SELECT ID FROM $wpdb->posts WHERE post_type = '".PLUGIN_CPT."';" );
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $wpdb->query( "DELETE FROM $wpdb->posts WHERE post_type = '".PLUGIN_CPT."';" );
    return $ids;
}

// Same hardcoded-table-name idiom generalized to a bare ALL_CAPS constant
// operand in place of a string literal, with and without an esc_sql() wrap.
define( 'PLUGIN_LOCATOR_TABLE', 'plugin_feed_locator' );
function create_locator_table() {
    global $wpdb;
    $locator_table_name = esc_sql( $wpdb->prefix . PLUGIN_LOCATOR_TABLE );
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $wpdb->query( "CREATE TABLE " . $locator_table_name . " (id BIGINT(20))" );
}

function alter_locator_table() {
    global $wpdb;
    $locator_table_name = $wpdb->prefix . PLUGIN_LOCATOR_TABLE;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $wpdb->query( "ALTER TABLE " . $locator_table_name . " ADD INDEX feed_id (feed_id)" );
}

// Negative control: table name built from prefix + a NON-constant (a lower-
// case parameter, not ALL_CAPS) must still fire — the constant-shape
// exclusion above must not overreach into a genuinely attacker-influenceable
// prior assignment of the same "$wpdb->prefix . $X" shape.
function alter_table_from_param( $suffix ) {
    global $wpdb;
    $table_name = $wpdb->prefix . $suffix;
    // ruleid: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $wpdb->query( "ALTER TABLE " . $table_name . " ADD INDEX feed_id (feed_id)" );
}

// Multi-segment double-quoted-string concat where every segment interpolates
// only $wpdb-> table-name properties (WordPress's own prefixed table-name
// globals), no other variable anywhere — the middle segment (bound as $VAR
// by the 3-element $BEFORE.$VAR.$AFTER pattern) is itself an interpolated
// string, a node shape distinct from a plain string literal that the bare
// "\"...\"" pattern-not does not cover on its own.
function count_reviews_by_rating() {
    global $wpdb;
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query_count = "SELECT commsm.meta_value AS rating, COUNT(comms.comment_ID) AS count FROM $wpdb->comments comms " .
    "INNER JOIN $wpdb->posts psts ON comms.comment_post_ID = psts.ID " .
    "INNER JOIN $wpdb->commentmeta commsm ON comms.comment_ID = commsm.comment_id " .
    "WHERE comms.comment_approved = '1' AND psts.post_type = 'product' AND commsm.meta_key = 'rating' " .
    "GROUP BY commsm.meta_value";
    return $wpdb->get_results( $query_count, OBJECT );
}

// Negative control: same multi-segment $wpdb-interpolated shape, but one
// segment (bound as $VAR) also interpolates a non-$wpdb variable — must
// still fire, proving the new exclusion isn't over-broad.
function count_reviews_by_rating_tainted( $order_id ) {
    global $wpdb;
    // ruleid: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query_count = "SELECT rating FROM $wpdb->comments comms " .
    "WHERE comment_post_ID = $order_id " .
    "AND comment_approved = '1'";
    return $wpdb->get_results( $query_count, OBJECT );
}

// Numeric-cast-earlier-in-function idiom: $offset is cast via intval() a few
// statements before the LIMIT-clause concatenation, not inline at the concat
// site itself — a very common paginated-export idiom. No SQL metacharacter
// can survive intval() regardless of how many statements separate the cast
// from the read.
function export_next_chunk() {
    global $wpdb;
    $offset = intval( $_POST['offset'] );
    // read next chunk from the database
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query_chunk = "SELECT * FROM " . $wpdb->prefix . "comments c " .
        "WHERE c.comment_approved = '1' " .
        "LIMIT " . $offset . ",100";
    return $wpdb->get_results( $query_chunk );
}

// Same idiom via an explicit (int) cast assignment instead of intval().
function export_next_chunk_int_cast() {
    global $wpdb;
    $offset = (int) $_POST['offset'];
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query_chunk = "SELECT * FROM " . $wpdb->prefix . "comments c LIMIT " . $offset;
    return $wpdb->get_results( $query_chunk );
}

// Variable-length IN() placeholder idiom: a %d placeholder skeleton is built
// via array_fill()/implode() (prepare()'s fixed-arity signature can't accept
// a dynamic-length argument list directly), then passed through prepare()
// indirectly via call_user_func_array(). $visible below already holds
// prepare()'s escaped output by the time it reaches the concatenation, even
// though the bare "$Q = $wpdb->prepare(...)" pattern-not can't see it
// (verified FP: wpdiscuz 7.6.62 WpdiscuzDBManager::commentIDsToRemove()).
function get_visible_comment_ids( $comment_ids ) {
    global $wpdb;
    $placeholders = " `comment_ID` IN(" . implode( ', ', array_fill( 0, count( $comment_ids ), '%d' ) ) . ") AND ";
    $visible = call_user_func_array( array( $wpdb, 'prepare' ), array_merge( array( $placeholders ), $comment_ids ) );
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query = "SELECT comment_ID FROM " . $wpdb->comments . " WHERE " . $visible . " comment_approved = '1'";
    return $wpdb->get_col( $query );
}

// Same idiom using PHP short-array call_user_func_array() syntax.
function get_visible_comment_ids_short_array( $comment_ids ) {
    global $wpdb;
    $placeholders = " `comment_ID` IN(" . implode( ', ', array_fill( 0, count( $comment_ids ), '%d' ) ) . ") AND ";
    $visible = call_user_func_array( [ $wpdb, 'prepare' ], array_merge( [ $placeholders ], $comment_ids ) );
    // ok: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query = "SELECT comment_ID FROM " . $wpdb->comments . " WHERE " . $visible . " comment_approved = '1'";
    return $wpdb->get_col( $query );
}

// Negative control: $visible is never routed through call_user_func_array()/
// prepare() at all -- must still fire, proving the new exclusion is scoped
// to the prepare()-assigned-earlier shape, not any variable named $visible.
function get_visible_comment_ids_unprepared( $raw_clause ) {
    global $wpdb;
    $visible = $raw_clause;
    // ruleid: claude.php.wordpress.sqli.bare-variable-concat-unprepared-wpdb-query
    $query = "SELECT comment_ID FROM " . $wpdb->comments . " WHERE " . $visible . " comment_approved = '1'";
    return $wpdb->get_col( $query );
}
