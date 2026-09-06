<?php
// Standalone companion script (downloader/webhook/cron) that bootstraps
// WordPress manually, outside the normal request lifecycle.

// ruleid: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require_once $downloader_data['wfu_ABSPATH'] . 'wp-load.php';

$config = json_decode($payload, true);
// ruleid: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require $config['base_path'] . 'wp-config.php';

$prefix = $_GET['abspath'];
$prefix = filter_var($prefix, FILTER_SANITIZE_URL);
// ruleid: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
include_once($prefix . 'wp-blog-header.php');

$root = $_COOKIE['wp_root'];
// ruleid: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
include($root . 'wp-settings.php');

// ok: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require_once ABSPATH . 'wp-load.php';

// ok: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require __DIR__ . '/wp-load.php';

// ok: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require_once dirname(__FILE__) . '/../../../wp-load.php';

// ok: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require_once MY_PLUGIN_ROOT . 'wp-load.php';

function wfu_update_download_status_safe($prefix2) {
	$prefix2 = realpath($prefix2);
	// ok: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
	require_once $prefix2 . 'wp-load.php';
}

// ok: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require '/var/www/html/wp-load.php';

// ok: claude.php.wordpress.rce.dynamic-path-prefix-wp-bootstrap-include
require_once ABSPATH . 'wp-admin/includes/file.php';
