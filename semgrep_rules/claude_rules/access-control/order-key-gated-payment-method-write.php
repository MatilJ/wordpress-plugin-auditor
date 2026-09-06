<?php
/**
 * Test cases for claude.php.wordpress.access-control.order-key-gated-payment-method-write
 */

// ── MATCH: order-key-only gate, no session/identity check ────────────────────
// Modeled on woo-stripe-payment 4.0.7 SubscriptionsController::process_change_payment_method_redirect().

class VulnerableSubscriptionsController {
    public function process_change_payment_method_redirect( $result, $gateway, $setup_intent ) {
        $id        = $_GET['order_id'];
        $order_key = $_GET['order_key'];
        $subscription = wc_get_order( absint( $id ) );
        // ruleid: claude.php.wordpress.access-control.order-key-gated-payment-method-write
        if ( ! $subscription || ! $subscription->key_is_valid( $order_key ) ) {
            return [ 'result' => 'error' ];
        }
        if ( $setup_intent->status === 'succeeded' ) {
            $gateway->set_payment_method_id( $setup_intent->payment_method->id );
        }
        return [ 'result' => 'success' ];
    }
}

// ── NO MATCH: sibling branch adds is_user_logged_in() + current-user binding ──

class SafeAddPaymentMethodHandler {
    public function save_payment_method_for_current_user( $order_key, $setup_intent ) {
        if ( ! is_user_logged_in() ) {
            return [ 'result' => 'error' ];
        }
        $order = wc_get_order( get_current_user_id() );
        // ok: claude.php.wordpress.access-control.order-key-gated-payment-method-write
        if ( ! $order || ! $order->key_is_valid( $order_key ) ) {
            return [ 'result' => 'error' ];
        }
        $order->set_payment_method_id( $setup_intent->payment_method->id );
        return [ 'result' => 'success' ];
    }
}

// ── NO MATCH: current_user_can() check present ────────────────────────────────

class SafeCapabilityCheckedHandler {
    public function update_payment_method_admin( $order_id, $order_key ) {
        if ( ! current_user_can( 'edit_shop_orders' ) ) {
            return [ 'result' => 'error' ];
        }
        $order = wc_get_order( $order_id );
        // ok: claude.php.wordpress.access-control.order-key-gated-payment-method-write
        if ( ! $order || ! $order->key_is_valid( $order_key ) ) {
            return [ 'result' => 'error' ];
        }
        $order->save_payment_method_id( 'stripe_cc' );
        return [ 'result' => 'success' ];
    }
}

// ── NO MATCH: function name doesn't match the payment-method-write pattern ────

class UnrelatedHandler {
    public function view_order_status( $order_id, $order_key ) {
        $order = wc_get_order( $order_id );
        // ok: claude.php.wordpress.access-control.order-key-gated-payment-method-write
        if ( ! $order || ! $order->key_is_valid( $order_key ) ) {
            return [ 'result' => 'error' ];
        }
        return [ 'status' => $order->get_status() ];
    }
}
