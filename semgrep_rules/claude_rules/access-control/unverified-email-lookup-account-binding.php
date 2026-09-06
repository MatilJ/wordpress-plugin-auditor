<?php

function ajax_checkout_handler_nopriv() {
    $email = sanitize_email( $_POST['checkout_email'] ?? '' );
    $user  = get_user_by( 'email', $email );
    $user_id = $user ? $user->ID : 0;

    $order = new Plugin_Order();
    // ruleid: claude.php.wordpress.access-control.unverified-email-lookup-account-binding
    $order->set_user_id( $user_id );
    $order->complete();
}

function ajax_booking_handler_nopriv() {
    $user = get_user_by( 'email', $_REQUEST['guest_email'] ?? '' );

    $booking = new Plugin_Booking();
    // ruleid: claude.php.wordpress.access-control.unverified-email-lookup-account-binding
    $booking->customer_id = $user->ID;
    $booking->save();
}

function ajax_checkout_handler_logged_in_or_guest() {
    $order = new Plugin_Order();

    if ( is_user_logged_in() ) {
        // ok: claude.php.wordpress.access-control.unverified-email-lookup-account-binding
        $order->set_user_id( get_current_user_id() );
    } else {
        $email = sanitize_email( $_POST['checkout_email'] ?? '' );
        $user  = get_user_by( 'email', $email );
        $order->set_user_id( $user ? $user->ID : 0 );
    }

    $order->complete();
}

function ajax_social_login_handler() {
    // Requires manual TRIAGE per the rule's item 2: a provider-token check
    // elsewhere in the function does not structurally exclude this sink —
    // only an is_user_logged_in()-gated branch does.
    $user = get_user_by( 'email', $_POST['email'] ?? '' );

    $order = new Plugin_Order();
    // ruleid: claude.php.wordpress.access-control.unverified-email-lookup-account-binding
    $order->set_user_id( $user->ID );
    $order->complete();
}
