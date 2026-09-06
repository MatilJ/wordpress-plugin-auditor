<?php
/**
 * activate-plugins.php — Safely activate WordPress plugins via direct DB.
 *
 * Usage:
 *   php activate-plugins.php <folder/file.php> [<folder/file.php> ...] [--with-hooks]
 *
 * Examples:
 *   php activate-plugins.php my-plugin/my-plugin.php
 *   php activate-plugins.php plugin-a/plugin-a.php plugin-b/plugin-b.php
 *   php activate-plugins.php my-plugin/my-plugin.php --with-hooks
 *
 * Without --with-hooks: DB-only (safe when plugins crash during init).
 * With --with-hooks: bootstraps WP to fire register_activation_hook() callbacks
 *   (creates tables, sets defaults, etc). May fail if another plugin crashes.
 */

$DB_HOST = getenv('WORDPRESS_DB_HOST') ?: 'db';
$DB_USER = getenv('WORDPRESS_DB_USER') ?: 'wordpress';
$DB_PASS = getenv('WORDPRESS_DB_PASSWORD') ?: 'wordpress';
$DB_NAME = getenv('WORDPRESS_DB_NAME') ?: 'wordpress';

$with_hooks = false;
$plugins_to_add = [];

foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--with-hooks') {
        $with_hooks = true;
    } else {
        $plugins_to_add[] = $arg;
    }
}

if (empty($plugins_to_add)) {
    fwrite(STDERR, "Usage: php activate-plugins.php <folder/file.php> [...] [--with-hooks]\n");
    exit(1);
}

$conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if ($conn->connect_error) {
    fwrite(STDERR, "DB connection failed: {$conn->connect_error}\n");
    exit(1);
}

$res = $conn->query("SELECT option_value FROM wp_options WHERE option_name='active_plugins'");
$row = $res->fetch_row();
$current = $row ? unserialize($row[0]) : [];
if (!is_array($current)) {
    $current = [];
}

echo "[*] Currently active: " . count($current) . " plugin(s)\n";
foreach ($current as $p) {
    echo "    - $p\n";
}

$added = [];
foreach ($plugins_to_add as $plugin) {
    if (in_array($plugin, $current, true)) {
        echo "[=] Already active: $plugin\n";
    } else {
        $current[] = $plugin;
        $added[] = $plugin;
        echo "[+] Adding: $plugin\n";
    }
}

if (!empty($added)) {
    $serialized = serialize(array_values($current));
    $stmt = $conn->prepare("UPDATE wp_options SET option_value=? WHERE option_name='active_plugins'");
    $stmt->bind_param('s', $serialized);
    $stmt->execute();
    echo "[*] Updated active_plugins (" . count($current) . " plugins, " . strlen($serialized) . " bytes)\n";
    echo "[*] Serialized: $serialized\n";
} else {
    echo "[*] No changes needed.\n";
}

$conn->close();

if ($with_hooks && !empty($added)) {
    echo "\n[*] Firing activation hooks (WP bootstrap)...\n";
    $_SERVER['HTTP_HOST'] = 'localhost';
    $_SERVER['REQUEST_URI'] = '/';
    require_once '/var/www/html/wp-load.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';

    foreach ($added as $plugin) {
        echo "    activate_plugin($plugin)... ";
        $result = activate_plugin($plugin, '', false, false);
        if (is_wp_error($result)) {
            echo "FAILED: " . $result->get_error_message() . "\n";
        } else {
            echo "OK\n";
        }
    }
}
