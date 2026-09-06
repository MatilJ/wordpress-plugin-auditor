<?php

// ---- TRUE POSITIVES ----

function tp_wp_mail_direct_post_to() {
    // ruleid: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($_POST['email'], 'Subject', 'Body');
}

function tp_wp_mail_variable_to() {
    $to = $_POST['recipient'];
    // ruleid: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($to, 'Notification', 'Your message');
}

function tp_mail_direct() {
    $to = $_REQUEST['to'];
    // ruleid: claude.php.wordpress.email.wp-mail-user-to-address
    mail($to, 'Subject', 'Body');
}

function tp_rest_param_to($request) {
    $email = $request->get_param('email');
    // ruleid: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($email, 'Reset', 'Click here to reset');
}

// ---- FALSE POSITIVES ----

function ok_wp_mail_sanitize_email() {
    $to = sanitize_email($_POST['email']);
    // ok: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($to, 'Subject', 'Body');
}

function ok_wp_mail_is_email_check() {
    $email = $_POST['email'];
    if (!is_email($email)) {
        return;
    }
    // ok: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($email, 'Subject', 'Body');
}

function ok_wp_mail_admin_email() {
    $admin = get_option('admin_email');
    // ok: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($admin, 'Contact Form', $_POST['message']);
}

function ok_wp_mail_filter_validate() {
    $to = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    // ok: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($to, 'Subject', 'Body');
}

function ok_wp_mail_hardcoded() {
    // ok: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail('admin@example.com', 'Alert', 'Something happened');
}

function ok_wp_mail_resolved_account_email_method() {
    $email = $_POST['email'];
    $user = get_user_by('email', $email);
    $to = $user->get('user_email');
    // ok: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($to, 'Password Reset', 'Click here to reset');
}

function ok_wp_mail_resolved_account_email_property() {
    $username = $_POST['username'];
    $user = get_user_by('login', $username);
    // ok: claude.php.wordpress.email.wp-mail-user-to-address
    wp_mail($user->user_email, 'Password Reset', 'Click here to reset');
}
