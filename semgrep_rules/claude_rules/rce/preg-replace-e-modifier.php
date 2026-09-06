<?php
// ruleid: claude.php.wordpress.rce.preg-replace-e-modifier
preg_replace("/([a-z]+)/e", "strtoupper('$1')", $_GET['input']);

// ruleid: claude.php.wordpress.rce.preg-replace-e-modifier
preg_replace('/foo/e', 'bar', $subject);

// ruleid: claude.php.wordpress.rce.preg-replace-e-modifier
preg_replace("#pattern#ie", "callback('$1')", $text);

// ruleid: claude.php.wordpress.rce.create-function-usage
$fn = create_function('$x', 'return $x * 2;');

// ruleid: claude.php.wordpress.rce.create-function-usage
$fn = create_function('', $_POST['body']);

// ok: claude.php.wordpress.rce.preg-replace-e-modifier
preg_replace("/foo/", "bar", $subject);

// ok: claude.php.wordpress.rce.preg-replace-e-modifier
preg_replace("/foo/i", "bar", $subject);

// ok: claude.php.wordpress.rce.preg-replace-e-modifier
preg_replace_callback("/foo/", function($m) { return strtoupper($m[0]); }, $subject);
