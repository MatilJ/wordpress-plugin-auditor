<?php
$from = $_POST['from'];
// ruleid: claude.php.wordpress.email.wp-mail-user-headers
wp_mail('admin@example.com', 'Subject', 'Body', "From: " . $from);

$reply = $_GET['reply_to'];
// ruleid: claude.php.wordpress.email.wp-mail-user-headers
wp_mail('admin@example.com', 'Subject', 'Body', ['Reply-To: ' . $reply]);

$cc = $_REQUEST['cc'];
// ruleid: claude.php.wordpress.email.wp-mail-user-headers
mail('admin@example.com', 'Subject', 'Body', "Cc: $cc");

// ok: claude.php.wordpress.email.wp-mail-user-headers
wp_mail('admin@example.com', 'Subject', 'Body', 'From: no-reply@example.com');

// ok: claude.php.wordpress.email.wp-mail-user-headers
$from = sanitize_text_field($_POST['from']);
wp_mail('admin@example.com', 'Subject', 'Body', "From: " . $from);

// ok: claude.php.wordpress.email.wp-mail-user-headers
// No $headers arg at all — not affected by this rule.
wp_mail($_POST['to'], 'Subject', 'Body');

// ok: claude.php.wordpress.email.wp-mail-user-headers
// sanitize_email() restricts to RFC email chars — excludes \r, \n, : — CRLF injection impossible.
$from_email = sanitize_email(wp_unslash($_POST['from_email']));
wp_mail('admin@example.com', 'Subject', 'Body', "From: " . $from_email);
