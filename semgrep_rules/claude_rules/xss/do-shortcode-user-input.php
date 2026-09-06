<?php

// Test cases for claude.php.wordpress.xss.do-shortcode-user-input

// ruleid: claude.php.wordpress.xss.do-shortcode-user-input
echo do_shortcode($_POST['content']);

// ruleid: claude.php.wordpress.xss.do-shortcode-user-input
$content = $_GET['shortcode'];
echo do_shortcode($content);

// ruleid: claude.php.wordpress.xss.do-shortcode-user-input
$body = wp_unslash($_REQUEST['body']);
$output = do_shortcode($body);
echo $output;

// ruleid: claude.php.wordpress.xss.do-shortcode-user-input
$text = sanitize_text_field($_POST['text']);
echo do_shortcode($text);

// ok: claude.php.wordpress.xss.do-shortcode-user-input
$safe = strip_shortcodes($_POST['content']);
echo do_shortcode($safe);

// ok: claude.php.wordpress.xss.do-shortcode-user-input
$safe = wp_strip_all_tags($_POST['content']);
echo do_shortcode($safe);

// ok: claude.php.wordpress.xss.do-shortcode-user-input
$safe = strip_tags($_POST['content']);
echo do_shortcode($safe);

// ok: claude.php.wordpress.xss.do-shortcode-user-input
$post = get_post();
echo do_shortcode($post->post_content);

// ─── apply_shortcodes() alias patterns ───────────────────────────────────────

// ruleid: claude.php.wordpress.xss.do-shortcode-user-input
echo apply_shortcodes($_POST['content']);

// ruleid: claude.php.wordpress.xss.do-shortcode-user-input
$sc = $_GET['shortcode'];
echo apply_shortcodes($sc);

// ruleid: claude.php.wordpress.xss.do-shortcode-user-input
$text = sanitize_text_field($_POST['text']);
echo apply_shortcodes($text);

// ok: claude.php.wordpress.xss.do-shortcode-user-input
$safe = strip_shortcodes($_POST['content']);
echo apply_shortcodes($safe);

// ok: claude.php.wordpress.xss.do-shortcode-user-input
$id = intval($_GET['id']);
echo apply_shortcodes('[gallery id="' . $id . '"]');
