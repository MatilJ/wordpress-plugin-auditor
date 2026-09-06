<?php
// Tests for claude.php.wordpress.access-control.hardcoded-hmac-key

global $wpdb;

// Hardcoded string literal key — TP.
// ruleid: claude.php.wordpress.access-control.hardcoded-hmac-key
$token = hash_hmac('md5', $appointment_id . $date_created, 'my-hardcoded-salt-string-committed-to-repo');

// Single-quoted hardcoded key — TP.
// ruleid: claude.php.wordpress.access-control.hardcoded-hmac-key
$sig = hash_hmac('sha256', $payload, 'another-secret-hardcoded-literal');

// AUTH_SALT constant — not a string literal, safe.
// ok: claude.php.wordpress.access-control.hardcoded-hmac-key
$token_safe = hash_hmac('md5', $data, AUTH_SALT);

// Key from database option — not a string literal, safe.
// ok: claude.php.wordpress.access-control.hardcoded-hmac-key
$secret = get_option('plugin_signing_secret');
$token_opt = hash_hmac('sha256', $data, $secret);

// Key from wp_hash() utility — not a string literal, safe.
// ok: claude.php.wordpress.access-control.hardcoded-hmac-key
$key = wp_hash($nonce_action);
$token_wp = hash_hmac('sha256', $data, $key);
