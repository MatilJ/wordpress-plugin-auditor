<?php

// Test cases for claude.php.wordpress.xss.server-self-uri-echo-xss

// ruleid: claude.php.wordpress.xss.server-self-uri-echo-xss
echo $_SERVER['REQUEST_URI'];

// ruleid: claude.php.wordpress.xss.server-self-uri-echo-xss
echo '<form action="' . $_SERVER['PHP_SELF'] . '">';

// ruleid: claude.php.wordpress.xss.server-self-uri-echo-xss
$script = $_SERVER['SCRIPT_NAME'];
echo $script;

// ruleid: claude.php.wordpress.xss.server-self-uri-echo-xss
printf('<input type="hidden" value="%s">', $_SERVER['REQUEST_URI']);

// ok: claude.php.wordpress.xss.server-self-uri-echo-xss
echo esc_url($_SERVER['REQUEST_URI']);

// ok: claude.php.wordpress.xss.server-self-uri-echo-xss
echo esc_attr($_SERVER['PHP_SELF']);

// ok: claude.php.wordpress.xss.server-self-uri-echo-xss
echo esc_html($_SERVER['SCRIPT_NAME']);

// ok: claude.php.wordpress.xss.server-self-uri-echo-xss
echo htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8');

// ok: claude.php.wordpress.xss.server-self-uri-echo-xss
$safe = esc_url($_SERVER['REQUEST_URI']);
echo '<form action="' . $safe . '">';
