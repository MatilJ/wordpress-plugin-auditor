<?php
// Test cases for claude.php.wordpress.access-control.broken-and-auth-check

// === TRUE POSITIVES — broken && patterns that bypass capability checks ===

// Three-condition form with !is_admin() in middle — exact Redux Framework pattern.
// For any logged-in user: !is_user_logged_in() = false → false && X && Y = false
// → wp_die() never fires, current_user_can() never evaluated.
function ajax_save_broken_three_way() {
    // ruleid: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! is_user_logged_in() && ! is_admin() && ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Access denied.' );
    }
    update_option( 'my_plugin_settings', $_POST['data'] );
}

// Two-condition form: !is_user_logged_in() && !current_user_can() — equally broken.
// Still bypassed by any logged-in user; current_user_can() never called.
function ajax_handler_broken_two_way() {
    // ruleid: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! is_user_logged_in() && ! current_user_can( 'edit_posts' ) ) {
        wp_die( 'Permission denied.' );
    }
    update_post_meta( absint( $_POST['post_id'] ), 'my_key', sanitize_text_field( $_POST['val'] ) );
}

// Reversed order: !is_admin() first, then !is_user_logged_in(), then !current_user_can().
function ajax_handler_reversed_order() {
    // ruleid: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! is_admin() && ! is_user_logged_in() && ! current_user_can( 'manage_options' ) ) {
        wp_die( 'No access.' );
    }
    update_option( 'theme_settings', $_POST['settings'] );
}

// Static method wrapper variant — exact redux-framework 4.5.11 class-redux-ajax-save.php:52 pattern.
// Redux_Helpers::current_user_can() wraps the native current_user_can() but the
// && short-circuit bug makes it equally dead code for any logged-in user.
class Redux_Helpers { public static function current_user_can( $cap ) { return current_user_can( $cap ); } }
function ajax_save_broken_static_wrapper() {
    // ruleid: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! is_admin() && ! is_user_logged_in() && ! Redux_Helpers::current_user_can( 'manage_options' ) ) {
        wp_die( 'Invalid capability.' );
    }
    update_option( 'redux_options', $_POST['data'] );
}

// Allow-list guard variant: !$VALUE && in_array($VALUE, [...]) as a
// "return if invalid" gate is always false — a value in the (non-empty
// string) list is truthy so !$VALUE is false, and a falsy value can't be
// a list member so in_array() is false; either way the && is false and
// the guard never returns, admitting any action value including ones
// outside the allow-list.
function dispatch_action_broken_allowlist() {
    $action = isset( $_GET['action'] ) ? sanitize_text_field( $_GET['action'] ) : false;
    // ruleid: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! $action && in_array( $action, [ 'update_item', 'delete_item' ] ) ) {
        return;
    }
    do_dispatch( $action );
}

// Same defect with a wp_die() body and a differently-named variable —
// confirms the pattern is not tied to a specific variable/action name.
function dispatch_mode_broken_allowlist( $mode ) {
    // ruleid: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! $mode && in_array( $mode, [ 'export', 'import' ] ) ) {
        wp_die( 'Invalid mode.' );
    }
    do_dispatch( $mode );
}

// === FALSE POSITIVES — correct || patterns that should NOT match ===

// Correct form using || — any single failing condition triggers wp_die().
// A Subscriber fails current_user_can('manage_options') → wp_die() fires.
function ajax_save_correct_or() {
    // ok: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Access denied.' );
    }
    update_option( 'my_plugin_settings', $_POST['data'] );
}

// Correct minimal form: only current_user_can() — no redundant login check needed
// since wp_ajax_ actions already require login via WordPress core.
function ajax_handler_correct_cap_only() {
    // ok: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_die( 'Permission denied.' );
    }
    update_post_meta( absint( $_POST['post_id'] ), 'my_key', sanitize_text_field( $_POST['val'] ) );
}

// Correct three-condition form using || throughout.
function ajax_handler_correct_three_way_or() {
    // ok: claude.php.wordpress.access-control.broken-and-auth-check
    if ( ! is_user_logged_in() || ! is_admin() || ! current_user_can( 'manage_options' ) ) {
        wp_die( 'No access.' );
    }
    update_option( 'theme_settings', $_POST['settings'] );
}

// Correct allow-list guard using || plus negated in_array() (De Morgan
// applied correctly) — returns unless the value is both set and allowed.
function dispatch_action_correct_allowlist() {
    // ok: claude.php.wordpress.access-control.broken-and-auth-check
    $action = isset( $_GET['action'] ) ? sanitize_text_field( $_GET['action'] ) : false;
    if ( ! $action || ! in_array( $action, [ 'update_item', 'delete_item' ] ) ) {
        return;
    }
    do_dispatch( $action );
}
