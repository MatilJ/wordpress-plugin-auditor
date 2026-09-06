<?php
/**
 * Mailpit Mailer — must-use plugin for the WP audit environment.
 *
 * Routes ALL WordPress mail — every wp_mail() call (WP core notifications and
 * the large majority of plugins) — to the Mailpit SMTP sink, so outbound email
 * is captured locally instead of leaving the sandbox. Inspect captured mail at:
 *
 *     http://localhost:8025
 *
 * General-purpose: not tied to any specific plugin. The target host/port come
 * from the MAILPIT_SMTP_HOST / MAILPIT_SMTP_PORT environment variables and
 * default to mailpit:1025 (the service defined in compose.yaml).
 *
 * NOTE: A plugin that sends through its OWN SMTP client (its own PHPMailer with
 * its own "SMTP" mail settings) bypasses wp_mail() and therefore this hook. To
 * capture that mail, set the plugin's SMTP settings to:
 *     host: mailpit   port: 1025   encryption: none   user/pass: anything
 * Mailpit is configured to accept any (or empty) credentials over plaintext.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action( 'phpmailer_init', function ( $phpmailer ) {
	$host = getenv( 'MAILPIT_SMTP_HOST' );
	$port = getenv( 'MAILPIT_SMTP_PORT' );

	$phpmailer->isSMTP();
	$phpmailer->Host        = $host ? $host : 'mailpit';
	$phpmailer->Port        = $port ? (int) $port : 1025;
	$phpmailer->SMTPAuth    = false; // Mailpit requires no authentication
	$phpmailer->SMTPAutoTLS = false; // never opportunistically upgrade to TLS
	$phpmailer->SMTPSecure  = '';    // plaintext connection
} );

/*
 * When the site runs on "localhost", WordPress' default sender is
 * wordpress@localhost, which PHPMailer rejects as an invalid address (no dot in
 * the domain), so every send fails before it reaches Mailpit. Supply a valid
 * fallback sender — but keep any valid From a plugin/caller already set, so the
 * captured mail still shows the real sender under test.
 */
add_filter( 'wp_mail_from', function ( $from ) {
	return ( $from && is_email( $from ) ) ? $from : 'wordpress@audit.local';
} );
