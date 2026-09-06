<?php

// Vulnerable: message body built from an unauthenticated REST body param
// (json-decoded template + a genuine per-user secret merged in) with no
// hash_equals()-based integrity check anywhere in the function.
function handle_forgot_password_test($request) {
    $form_data  = $request->get_body_params();
    $subject    = 'Password Reset';
    $email_body = $form_data['emailBody'];

    $key        = get_password_reset_key($user);
    $reset_link = "https://example.com/reset?key=$key";
    $email_body = $email_body . $reset_link;

    $headers = array('Content-Type: text/html; charset=UTF-8');
    // ruleid: claude.php.wordpress.access-control.wp-mail-content-no-signature-check
    wp_mail($email, $subject, $email_body, $headers);
}

// Vulnerable: subject taken directly from $_POST, no hash_equals() guard
// anywhere in the function.
function ajax_send_custom_email_test() {
    $subject = $_POST['subject'];
    $message = 'Fixed static message body.';
    // ruleid: claude.php.wordpress.access-control.wp-mail-content-no-signature-check
    wp_mail('admin@example.com', $subject, $message);
}

// Fixed: the submitted subject/body is verified against a server-computed
// HMAC via hash_equals() before it is used — the real remediation.
function handle_forgot_password_fixed_test($request) {
    $form_data = $request->get_body_params();
    $subject   = $form_data['emailSubject'];
    $body_raw  = $form_data['emailBody'];
    $signature = $form_data['emailSignature'];

    $expected = hash_hmac('sha256', $subject . '|' . $body_raw, AUTH_KEY . AUTH_SALT);
    if (!hash_equals($expected, $signature)) {
        wp_send_json_error('Invalid request', 400);
        exit;
    }

    $email_body_array = json_decode($body_raw, true);
    $headers = array('Content-Type: text/html; charset=UTF-8');
    // ok: claude.php.wordpress.access-control.wp-mail-content-no-signature-check
    wp_mail($email, $subject, $email_body_array['text'], $headers);
}

// Safe: subject/body come from server-stored (admin-configured) settings,
// not from the live request.
function send_notification_from_settings_test() {
    $settings = get_option('my_plugin_email_settings');
    $subject  = $settings['subject'];
    $body     = $settings['body'];
    // ok: claude.php.wordpress.access-control.wp-mail-content-no-signature-check
    wp_mail('admin@example.com', $subject, $body);
}
