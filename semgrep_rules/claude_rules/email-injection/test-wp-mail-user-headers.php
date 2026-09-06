<?php
// Test file for wp-mail-user-headers rule — int cast sanitizer additions

function bad_mail_headers() {
    $headers = $_POST['headers'];
    // ruleid: claude.php.wordpress.email.wp-mail-user-headers
    wp_mail('to@example.com', 'Subject', 'Body', $headers);
}

function good_mail_sanitize_text_field() {
    $from = sanitize_text_field($_POST['from']);
    // ok: claude.php.wordpress.email.wp-mail-user-headers
    wp_mail('to@example.com', 'Subject', 'Body', 'From: ' . $from);
}

function good_mail_intval() {
    $id = intval($_POST['id']);
    // ok: claude.php.wordpress.email.wp-mail-user-headers
    wp_mail('to@example.com', 'Subject', 'Body', 'X-ID: ' . $id);
}

function good_mail_int_cast() {
    $id = (int) $_POST['id'];
    // ok: claude.php.wordpress.email.wp-mail-user-headers
    wp_mail('to@example.com', 'Subject', 'Body', 'X-ID: ' . $id);
}
