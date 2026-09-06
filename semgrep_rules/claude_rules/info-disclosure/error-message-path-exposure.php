<?php

// --- TRUE POSITIVES ---

function handle_error_die() {
    try {
        do_something();
    } catch (Exception $e) {
        // ruleid: claude.php.wordpress.info-disclosure.error-message-path-exposure
        wp_die($e->getMessage());
    }
}

function handle_error_json() {
    try {
        process_data();
    } catch (Exception $e) {
        $msg = $e->getMessage();
        // ruleid: claude.php.wordpress.info-disclosure.error-message-path-exposure
        wp_send_json_error($msg);
    }
}

function handle_db_error() {
    global $wpdb;
    $wpdb->query("SELECT ...");
    $err = $wpdb->last_error;
    // ruleid: claude.php.wordpress.info-disclosure.error-message-path-exposure
    wp_die($err);
}

function expose_trace() {
    try {
        fail();
    } catch (Exception $e) {
        $trace = $e->getTraceAsString();
        // ruleid: claude.php.wordpress.info-disclosure.error-message-path-exposure
        echo $trace;
    }
}

// --- TRUE NEGATIVES ---

function safe_error_handling() {
    try {
        do_something();
    } catch (Exception $e) {
        error_log($e->getMessage());
        // ok: claude.php.wordpress.info-disclosure.error-message-path-exposure
        wp_die(__('An error occurred.'));
    }
}

function safe_static_die() {
    // ok: claude.php.wordpress.info-disclosure.error-message-path-exposure
    wp_die('Access denied.');
}

function safe_json_error() {
    // ok: claude.php.wordpress.info-disclosure.error-message-path-exposure
    wp_send_json_error(array('code' => 'invalid_request'));
}

// Same-function current_user_can() gate — only a role that already passed the
// capability check reaches the exception detail. Confirmed FP:
// woocommerce-pdf-invoices-packing-slips 5.15.2 wcpdf_output_error().
function gated_error_output(string $message, ?Throwable $e = null) {
    if (!current_user_can('edit_shop_orders')) {
        esc_html_e('Error, please contact the site owner.');
        return;
    }
    if ($e instanceof Throwable) {
        // ok: claude.php.wordpress.info-disclosure.error-message-path-exposure
        echo esc_html($e->getFile()) . ' (' . esc_html((string) $e->getLine()) . ')';
    }
}

function ungated_error_output_still_matches() {
    try {
        do_something();
    } catch (Exception $e) {
        // ruleid: claude.php.wordpress.info-disclosure.error-message-path-exposure
        wp_die($e->getMessage());
    }
}
