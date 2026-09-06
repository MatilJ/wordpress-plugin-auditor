<?php

class Guest_Order_Document_Handler {

	public static function print_document_from_the_mail_link( $order, $access_key, $decoded_mail_id, $decoded_order_id ) {
		// ruleid: claude.php.wordpress.access-control.email-match-order-ownership-bypass
		if ( hash_equals( $order->get_order_key(), $access_key ) ) {
			$orders = explode( ',', $decoded_order_id );
		} elseif ( $decoded_mail_id === ( $order->get_billing_email() ) ) {
			$orders = explode( ',', $decoded_order_id );
		} else {
			wp_die( 'It seems this order is not yours.' );
		}
		return $orders;
	}

	public static function resolve_invoice_access( $order, $requested_key, $requested_phone ) {
		// ruleid: claude.php.wordpress.access-control.email-match-order-ownership-bypass
		if ( $order->key_is_valid( $requested_key ) ) {
			return true;
		} elseif ( $order->get_billing_phone() == $requested_phone ) {
			return true;
		}
		return false;
	}

	public static function resolve_reorder_link( $order, $access_key, $requested_id ) {
		// $GETTER is get_id(), not a billing email/phone identifier — a
		// non-secret order id is a different (and separately scoped) risk,
		// not the identity-match shape this rule targets.
		// ok: claude.php.wordpress.access-control.email-match-order-ownership-bypass
		if ( hash_equals( $order->get_order_key(), $access_key ) ) {
			return true;
		} elseif ( $requested_id === $order->get_id() ) {
			return true;
		}
		return false;
	}

	public static function is_order_owner_by_email( $order, $decoded_mail_id ) {
		// A bare email-equality check with no sibling secret-comparison
		// branch is a different (broader) vulnerability shape, out of scope
		// for this rule, which specifically targets the OR'd-alongside-a-
		// legitimate-secret-check structure.
		// ok: claude.php.wordpress.access-control.email-match-order-ownership-bypass
		if ( $decoded_mail_id === $order->get_billing_email() ) {
			return true;
		}
		return false;
	}
}
