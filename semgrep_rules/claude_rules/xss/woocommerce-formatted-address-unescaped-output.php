<?php
/**
 * Test cases for:
 *   claude.php.wordpress.xss.woocommerce-formatted-address-unescaped-output (taint)
 */

// ── TPs ──────────────────────────────────────────────────────────────────────

function get_billing_block( $order ) {
    if ( $address = $order->get_formatted_billing_address() ) {
        $address = apply_filters( 'my_billing_address', $address );
    } else {
        $address = 'N/A';
    }
    // ruleid: claude.php.wordpress.xss.woocommerce-formatted-address-unescaped-output
    return $address;
}

function echo_shipping_address( $order ) {
    $address = $order->get_formatted_shipping_address();
    // ruleid: claude.php.wordpress.xss.woocommerce-formatted-address-unescaped-output
    echo $address;
}

// ── OKs ──────────────────────────────────────────────────────────────────────

function get_billing_block_sanitized( $order ) {
    if ( $address = $order->get_formatted_billing_address() ) {
        $address = apply_filters( 'my_billing_address', my_plugin_sanitize_html_content( $address ) );
    } else {
        $address = 'N/A';
    }
    // ok: claude.php.wordpress.xss.woocommerce-formatted-address-unescaped-output
    return $address;
}

function echo_shipping_address_escaped( $order ) {
    $address = $order->get_formatted_shipping_address();
    $address = wp_kses( $address, array( 'br' => array() ) );
    // ok: claude.php.wordpress.xss.woocommerce-formatted-address-unescaped-output
    echo $address;
}
