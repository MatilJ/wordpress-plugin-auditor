<?php
/**
 * Test cases for claude.php.wordpress.access-control.wc-order-received-no-key-check
 *
 * TRUE POSITIVE: wc_get_order() uses query_vars['order-received'] with no order key validation.
 * FALSE POSITIVE / OK: same call but the function also validates the order key before use.
 */

// ── MATCH: standalone function, no key check ─────────────────────────────────

function tracker_order_received_vulnerable() {
    global $wp_query;
    // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
    $order = wc_get_order( $wp_query->query_vars['order-received'] );
    if ( $order ) {
        $data = [ 'value' => $order->get_total(), 'currency' => $order->get_currency() ];
        echo json_encode( $data );
    }
}

// ── MATCH: class method (tracker pixel pattern), no key check ─────────────────

class VulnerablePixelTracker {
    protected function order_received() {
        global $wp_query;
        // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
        $order = wc_get_order( $wp_query->query_vars['order-received'] );
        if ( $order ) {
            echo json_encode( [ 'value' => $order->get_total() ] );
        }
    }
}

// ── NO MATCH: get_query_var('order-key') called in the same function ──────────

function tracker_order_received_key_via_get_query_var() {
    global $wp_query;
    // ok: claude.php.wordpress.access-control.wc-order-received-no-key-check
    $order     = wc_get_order( $wp_query->query_vars['order-received'] );
    $order_key = get_query_var( 'order-key' );
    if ( ! $order || ! hash_equals( $order->get_order_key(), $order_key ) ) {
        return;
    }
    echo json_encode( [ 'value' => $order->get_total() ] );
}

// ── NO MATCH: order key retrieved via $order->get_order_key() assignment ─────

function tracker_order_received_key_via_method() {
    global $wp_query;
    // ok: claude.php.wordpress.access-control.wc-order-received-no-key-check
    $order       = wc_get_order( $wp_query->query_vars['order-received'] );
    $stored_key  = $order->get_order_key();
    $request_key = isset( $_GET['key'] ) ? sanitize_text_field( wp_unslash( $_GET['key'] ) ) : '';
    if ( ! $order || ! hash_equals( $stored_key, $request_key ) ) {
        return;
    }
    echo json_encode( [ 'value' => $order->get_total() ] );
}

// ── MATCH: 'order-pay' variant, no key check ──────────────────────────────────
// Confirmed TP: woo-stripe-payment 4.0.7 ContextHandler::get_order_from_query(),
// reached from a wp_print_footer_scripts callback with no key/ownership check.

function get_order_from_query_vulnerable() {
    global $wp;
    // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
    return wc_get_order( absint( $wp->query_vars['order-pay'] ) );
}

class VulnerableFooterDataInjector {
    public function get_order_from_query() {
        global $wp;
        // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
        return wc_get_order( absint( $wp->query_vars['order-pay'] ) );
    }
}

// ── NO MATCH: 'order-pay' variant, key_is_valid() checked in the same function ─

function get_order_from_query_key_checked() {
    global $wp;
    // ok: claude.php.wordpress.access-control.wc-order-received-no-key-check
    $order = wc_get_order( absint( $wp->query_vars['order-pay'] ) );
    if ( ! $order || ! $order->key_is_valid( $_GET['key'] ) ) {
        return null;
    }
    return $order;
}

// ── MATCH: 'view-order' variant, no key check — sibling shortcode shape ───────
// Confirmed TP: woocommerce-pdf-invoices-packing-slips 5.15.2
// Frontend::generate_document_shortcode() resolves both 'order-received' and
// this 'view-order' branch from the same function with no key check.

function generate_document_shortcode_vulnerable() {
    global $wp;
    if ( is_checkout() && isset( $wp->query_vars['order-received'] ) ) {
        // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
        $order = wc_get_order( $wp->query_vars['order-received'] );
    } elseif ( is_account_page() && isset( $wp->query_vars['view-order'] ) ) {
        // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
        $order = wc_get_order( $wp->query_vars['view-order'] );
    }
    if ( $order ) {
        echo esc_url( admin_url( 'admin-ajax.php?action=generate_doc&order_ids=' . $order->get_id() . '&access_key=' . $order->get_order_key() ) );
    }
}

// ── NO MATCH: 'view-order' variant, hash_equals() gates the read ──────────────

function view_order_key_checked() {
    global $wp;
    // ok: claude.php.wordpress.access-control.wc-order-received-no-key-check
    $order = wc_get_order( absint( $wp->query_vars['view-order'] ) );
    $request_key = isset( $_GET['key'] ) ? sanitize_text_field( $_GET['key'] ) : '';
    if ( ! $order || ! hash_equals( $order->get_order_key(), $request_key ) ) {
        return;
    }
    echo json_encode( [ 'email' => $order->get_billing_email() ] );
}

// ── MATCH: 'view-order' variable-indirection shape ─────────────────────────

function get_order_from_view_order_var() {
    global $wp;
    $order_id = absint( $wp->query_vars['view-order'] );
    // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
    $order = wc_get_order( $order_id );
    if ( $order ) {
        echo json_encode( [ 'value' => $order->get_total() ] );
    }
}

// ── MATCH: variable-indirection shape — order ID assigned from query_vars
// into a local variable (nested inside its own if-block), then consumed by
// wc_get_order() later in the same function, gated only by a non-empty check
// on the request key rather than an equality comparison against the order's
// own key. Mirrors the pixelyoursite 11.2.1 getAdvancedMatchingParams() shape.

function get_advanced_matching_params_vulnerable() {
    if ( isset( $_REQUEST['key'] ) && $_REQUEST['key'] != "" ) {
        $order_key = sanitize_key( $_REQUEST['key'] );
        $cache_key = 'order_id_' . $order_key;
        $order_id  = get_transient( $cache_key );
        global $wp;
        if ( empty( $order_id ) && $wp->query_vars['order-received'] ) {
            $order_id = absint( $wp->query_vars['order-received'] );
            if ( $order_id ) {
                set_transient( $cache_key, $order_id, HOUR_IN_SECONDS );
            }
        }
        if ( empty( $order_id ) ) {
            $order_id = (int) wc_get_order_id_by_order_key( $order_key );
            set_transient( $cache_key, $order_id, HOUR_IN_SECONDS );
        }
        // ruleid: claude.php.wordpress.access-control.wc-order-received-no-key-check
        $order = wc_get_order( $order_id );
        if ( $order ) {
            echo json_encode( [ 'email' => $order->get_billing_email() ] );
        }
    }
}

// ── NO MATCH: variable-indirection shape, but hash_equals() gates the read ──

function get_advanced_matching_params_safe_hash_equals() {
    global $wp;
    if ( ! empty( $wp->query_vars['order-received'] ) ) {
        $order_id = absint( $wp->query_vars['order-received'] );
        // ok: claude.php.wordpress.access-control.wc-order-received-no-key-check
        $order = wc_get_order( $order_id );
        $request_key = isset( $_GET['key'] ) ? sanitize_text_field( $_GET['key'] ) : '';
        if ( ! $order || ! hash_equals( $order->get_order_key(), $request_key ) ) {
            return;
        }
        echo json_encode( [ 'email' => $order->get_billing_email() ] );
    }
}
