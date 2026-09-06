<?php
// sql-keyword-blocklist-sanitizer rule test cases

// ── VULNERABLE PATTERNS ──────────────────────────────────────────────────────

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/select(.*?)from/im', $search, $matches);

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/delete(.*?)from/im', $user_input, $matches2);

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/update(.*?)set/im', $query_string, $m);

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/insert(.*?)into/im', $val, $matches3);

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/union(.*?)select/im', $s, $m2);

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/select.*from/i', $input, $found);

// ruleid: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match_all('/select.{0,20}from/i', $raw, $all_matches);


// ── SAFE PATTERNS ────────────────────────────────────────────────────────────

// ok: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/^https?:[a-z]/i', $url, $m);

// ok: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/<script[^>]*>/i', $content, $script_match);

// ok: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/^\d+$/', $id, $numeric);

// ok: claude.php.wordpress.sqli.sql-keyword-blocklist-sanitizer
preg_match('/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i', $email, $email_match);
