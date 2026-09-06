<?php
// Tests for claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token

// Real-world shape (CVE-2024-50550): cast/float/multiply around microtime(), TP.
// ruleid: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
mt_srand((int) ((float) microtime() * 1000000));

// Bare microtime() seed, TP.
// ruleid: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
mt_srand(microtime());

// time() seed, TP.
// ruleid: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
mt_srand((int) time());

// date()-derived seed, TP.
// ruleid: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
mt_srand((int) date('U'));

// Fixed, non-time seed for reproducible test fixtures — not the antipattern, safe.
// ok: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
mt_srand(12345);

// No manual reseed at all — the actual upstream fix — safe.
// ok: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
$token = bin2hex(random_bytes(16));

// mt_rand() alone, no reseed call present — safe (different node entirely).
// ok: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
$n = mt_rand(0, 100);

// Seed derived from a per-request nonce, not time — safe.
// ok: claude.php.wordpress.access-control.mt-srand-time-seeded-weak-token
mt_srand($unique_request_nonce);
