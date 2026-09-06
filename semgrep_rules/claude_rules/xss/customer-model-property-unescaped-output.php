<?php
/**
 * Test cases for:
 *   claude.php.wordpress.xss.customer-model-property-unescaped-output  (taint)
 *   claude.php.wordpress.xss.customer-model-property-html-concat       (pattern)
 */

// ── Taint-mode TPs ─────────────────────────────────────────────────────────

function column_customer_return( $invoice ) {
	$customer = $invoice->checkout->customer ?? null;
	$url      = get_edit_url( $customer->id );
	$name     = $customer->name;
	// ruleid: claude.php.wordpress.xss.customer-model-property-unescaped-output
	return '<a href="' . esc_url( $url ) . '">' . $name . '</a>';
}

function column_customer_email_echo( $checkout ) {
	$email = $checkout->customer->email;
	// ruleid: claude.php.wordpress.xss.customer-model-property-unescaped-output
	echo $email;
}

// ── Taint-mode OKs ─────────────────────────────────────────────────────────

function column_customer_return_fixed( $invoice ) {
	$customer = $invoice->checkout->customer ?? null;
	$url      = get_edit_url( $customer->id );
	// ok: claude.php.wordpress.xss.customer-model-property-unescaped-output
	return '<a href="' . esc_url( $url ) . '">' . esc_html( $customer->name ) . '</a>';
}

function column_customer_email_echo_fixed( $checkout ) {
	// ok: claude.php.wordpress.xss.customer-model-property-unescaped-output
	echo esc_html( $checkout->customer->email );
}

function column_product_name_not_customer( $subscription ) {
	// ok: claude.php.wordpress.xss.customer-model-property-unescaped-output
	return '<a href="#">' . $subscription->price->product->name . '</a>';
}

// ── Pattern-mode TPs ───────────────────────────────────────────────────────

// ruleid: claude.php.wordpress.xss.customer-model-property-html-concat
$html = '<a href="#">' . $customer->name . '</a>';

// ruleid: claude.php.wordpress.xss.customer-model-property-html-concat
$msg = 'Hello ' . $checkout->customer->email . '!';

// ── Pattern-mode OKs ───────────────────────────────────────────────────────

// ok: claude.php.wordpress.xss.customer-model-property-html-concat
$safe_html = '<a href="#">' . esc_html( $customer->name ) . '</a>';

// ok: claude.php.wordpress.xss.customer-model-property-html-concat
$safe_msg = 'Hello ' . esc_html( $checkout->customer->email ) . '!';

// ok: claude.php.wordpress.xss.customer-model-property-html-concat
$safe_product = '<a href="#">' . $subscription->price->product->name . '</a>';
