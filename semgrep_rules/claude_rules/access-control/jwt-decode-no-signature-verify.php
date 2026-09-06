<?php
// Tests for claude.php.wordpress.access-control.jwt-decode-no-signature-verify

// Vulnerable: manual JWT parsing with no signature verification — TP.
// ruleid: claude.php.wordpress.access-control.jwt-decode-no-signature-verify
$parts = explode('.', $jwt_token);
$payload = base64_decode($parts[1]);
$data = json_decode($payload, true);

// Safe: hash_hmac verification between explode and base64_decode — FP.
// ok: claude.php.wordpress.access-control.jwt-decode-no-signature-verify
$parts2 = explode('.', $jwt_token);
$sig_valid = hash_hmac('sha256', $parts2[0] . '.' . $parts2[1], $secret);
$payload2 = base64_decode($parts2[1]);
$data2 = json_decode($payload2, true);

// Safe: openssl_verify after base64_decode — FP.
// ok: claude.php.wordpress.access-control.jwt-decode-no-signature-verify
$parts3 = explode('.', $jwt_token);
$payload3 = base64_decode($parts3[1]);
openssl_verify($parts3[0] . '.' . $parts3[1], base64_decode($parts3[2]), $public_key, OPENSSL_ALGO_SHA256);
$data3 = json_decode($payload3, true);
