<?php
// Tests for claude.php.wordpress.access-control.empty-secret-jwt-validation

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Vulnerable: get_option secret used in JWT::decode without empty check — TP.
// ruleid: claude.php.wordpress.access-control.empty-secret-jwt-validation
$secret = get_option('jwt_secret');
$decoded = JWT::decode($token, new Key($secret, 'HS256'));

// Safe: empty() guard before JWT::decode — FP.
// ok: claude.php.wordpress.access-control.empty-secret-jwt-validation
$secret2 = get_option('jwt_secret');
if (empty($secret2)) { wp_die('Not configured'); }
$decoded2 = JWT::decode($token, new Key($secret2, 'HS256'));

// Safe: falsy guard before JWT::decode — FP.
// ok: claude.php.wordpress.access-control.empty-secret-jwt-validation
$secret3 = get_option('jwt_secret');
if (!$secret3) { wp_die('Secret missing'); }
$decoded3 = JWT::decode($token, new Key($secret3, 'HS256'));
