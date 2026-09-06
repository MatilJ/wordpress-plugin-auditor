<?php
/**
 * Test cases for:
 *   claude.php.wordpress.xss.woocommerce-order-billing-unescaped-output  (taint)
 *   claude.php.wordpress.xss.woocommerce-order-billing-html-concat       (pattern)
 */

// ── Taint-mode TPs ─────────────────────────────────────────────────────────

function bad_direct_echo( $order ) {
    $name = $order->get_billing_first_name();
    // ruleid: claude.php.wordpress.xss.woocommerce-order-billing-unescaped-output
    echo $name;
}

function bad_via_array_json_echo( $order ) {
    $data         = array();
    $data['city'] = $order->get_billing_city();
    // ruleid: claude.php.wordpress.xss.woocommerce-order-billing-unescaped-output
    echo json_encode( $data );
}

// ── Taint-mode OKs ─────────────────────────────────────────────────────────

function good_esc_html_echo( $order ) {
    // ok: claude.php.wordpress.xss.woocommerce-order-billing-unescaped-output
    echo esc_html( $order->get_billing_first_name() );
}

function good_sanitize_before_echo( $order ) {
    $city = sanitize_text_field( $order->get_billing_city() );
    // ok: claude.php.wordpress.xss.woocommerce-order-billing-unescaped-output
    echo $city;
}

function good_wp_send_json( $order ) {
    $data          = array();
    $data['state'] = $order->get_billing_state();
    // ok: claude.php.wordpress.xss.woocommerce-order-billing-unescaped-output
    wp_send_json( $data );
}

// ── Pattern-mode TPs ───────────────────────────────────────────────────────

// ruleid: claude.php.wordpress.xss.woocommerce-order-billing-html-concat
$html = '<span class="name">' . $order->get_billing_first_name() . '</span>';

// ruleid: claude.php.wordpress.xss.woocommerce-order-billing-html-concat
$msg = 'Order from ' . $order->get_billing_city() . '!';

// ruleid: claude.php.wordpress.xss.woocommerce-order-billing-html-concat
$note = 'Note: ' . $order->get_customer_note() . '.';

// ── Pattern-mode OKs ───────────────────────────────────────────────────────

// ok: claude.php.wordpress.xss.woocommerce-order-billing-html-concat
$safe_name = 'Hello ' . esc_html( $order->get_billing_first_name() ) . '!';

// ok: claude.php.wordpress.xss.woocommerce-order-billing-html-concat
$safe_city = 'City: ' . esc_html( $order->get_billing_city() ) . '.';

// ok: claude.php.wordpress.xss.woocommerce-order-billing-html-concat
$safe_state = 'Region: ' . sanitize_text_field( $order->get_billing_state() ) . '.';
