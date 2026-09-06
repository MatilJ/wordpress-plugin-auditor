<?php
// ruleid: claude.php.wordpress.rce.command-injection
system("ls " . $_GET['dir']);

$host = $_POST['host'];
// ruleid: claude.php.wordpress.rce.command-injection
shell_exec("ping -c 1 $host");

$cmd = $_REQUEST['cmd'];
// ruleid: claude.php.wordpress.rce.command-injection
exec($cmd, $out, $ret);

// ruleid: claude.php.wordpress.rce.command-injection
passthru("convert " . $_POST['file'] . " out.png");

$ua = $_SERVER['HTTP_USER_AGENT'];
// ruleid: claude.php.wordpress.rce.command-injection
popen("echo $ua >> /var/log/ua.log", "r");

$url = $_GET['url'];
// ruleid: claude.php.wordpress.rce.command-injection
proc_open("curl " . $url, [], $pipes);

// ok: claude.php.wordpress.rce.command-injection
system("ls /tmp");

// ok: claude.php.wordpress.rce.command-injection
$safe = escapeshellarg($_POST['file']);
system("convert " . $safe . " out.png");

// ok: claude.php.wordpress.rce.command-injection
$dir = escapeshellarg($_GET['dir']);
shell_exec("ls " . $dir);

// ok: claude.php.wordpress.rce.command-injection
$cmd = escapeshellcmd($_REQUEST['cmd']);
exec($cmd);
