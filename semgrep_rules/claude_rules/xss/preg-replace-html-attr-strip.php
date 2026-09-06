<?php
/**
 * Test cases for preg-replace-html-attr-strip.yaml
 * Rule id: claude.php.wordpress.xss.preg-replace-html-attr-strip
 *
 * Confirmed TP: Schema & Structured Data for WP & AMP — CVE-2025-9512
 *   preg_replace('/itemprop="(.*?)"/', '', $content) on comment content;
 *   mixed-quote injection promotes onfocus/autofocus into element → Stored XSS.
 *
 * Reference: https://sec.stealthcopter.com/regexss
 */

// ── Vulnerable patterns (RegExSS) ────────────────────────────────────────────

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$content = preg_replace('/itemprop\=\"(.*?)\"/', "", $content);

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$content = preg_replace('/onclick=".*?"/', '$1', $content);

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$content = preg_replace('/data-target=".*?"/', '', $content);

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$html = preg_replace('#style="[^"]*"#', '', $html);

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$content = preg_replace('/(<[^>]+) aria-current=".*?"/', '$1', $content);

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$content = preg_replace('/(<[^>]+) onclick=".*?"/', '$1', $content);

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$output = preg_replace('/ class=".*?"/', '', $output);

// ruleid: claude.php.wordpress.xss.preg-replace-html-attr-strip
$text = preg_replace('/srcset="(.*?)"/', '', $text);

// ── Safe patterns (should NOT match) ─────────────────────────────────────────

// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$safe1 = preg_replace('/[^a-zA-Z0-9]/', '', $input);

// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$safe2 = preg_replace('/\s+/', ' ', $text);

// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$safe3 = str_replace('onclick', '', $html);

// BBCode converter — not HTML attribute stripping
// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$bbcode = preg_replace('/\[quote="(.*?)":(.*?)\]/', '<em>@$1 wrote:</em><blockquote>', $bbcode);

// BBCode size tag — not HTML
// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$bbcode2 = preg_replace('/\[size=(.*?)\]/', '<span style="font-size:$1">', $bbcode2);

// JSON-LD script removal — not attribute stripping
// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$content = preg_replace('/<script type=\"application\/ld\+json" class=\"aioseop-schema"\>(.*?)<\/script>/', "", $content);

// Script element removal — not attribute stripping
// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$content = preg_replace('/<script[^>]*>.*?<\/script>/i', '', $content);

// Smiley replacement — not HTML attribute stripping
// ok: claude.php.wordpress.xss.preg-replace-html-attr-strip
$markup = preg_replace('/\<img src=(.*?)EMO_DIR(.*?)bbc_emoticon(.*?)alt=\'(.*?)\' \/\>/', '$4', $markup);
