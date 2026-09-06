<?php

function handle_request_otp() {
    // ruleid: claude.php.wordpress.access-control.otp-value-returned-in-json-response
    $otp = Sms_Gateway::sendOTPSMS( $phone_code, $phone_no );

    if ( is_wp_error( $otp ) ) {
        return;
    }

    wp_send_json( array(
        'otp_sent' => 1,
        'otp'      => $otp,
        'phone'    => $phone_code . $phone_no,
    ) );
}

function ajax_verify_start() {
    // ruleid: claude.php.wordpress.access-control.otp-value-returned-in-json-response
    $verification_code = generate_verification_code( $email );

    wp_send_json_success( array(
        'sent'              => true,
        'verification_code' => $verification_code,
    ) );
}

function handle_request_otp_inline() {
    // ruleid: claude.php.wordpress.access-control.otp-value-returned-in-json-response
    wp_send_json( array(
        'otp_sent' => 1,
        'otp'      => send_otp_sms( $phone_code, $phone_no ),
    ) );
}

// ok: claude.php.wordpress.access-control.otp-value-returned-in-json-response
function handle_request_otp_fixed() {
    $otp = Sms_Gateway::sendOTPSMS( $phone_code, $phone_no );

    if ( is_wp_error( $otp ) ) {
        return;
    }

    wp_send_json( array(
        'otp_sent' => 1,
        //'otp'    => $otp,
        'phone'    => $phone_code . $phone_no,
    ) );
}

// ok: claude.php.wordpress.access-control.otp-value-returned-in-json-response
function handle_order_lookup() {
    $order_code = get_post_meta( $order_id, 'order_reference_code', true );

    wp_send_json_success( array(
        'found'      => true,
        'order_code' => $order_code,
    ) );
}
