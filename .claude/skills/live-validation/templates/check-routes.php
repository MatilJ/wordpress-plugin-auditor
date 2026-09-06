<?php
/**
 * check-routes.php — List registered WordPress REST API routes.
 *
 * Usage:
 *   php check-routes.php              (all routes)
 *   php check-routes.php myplugin     (routes containing "myplugin")
 *   php check-routes.php myplugin/v1  (routes in a specific namespace)
 *
 * docker compose exec -T wordpress php /tmp/check-routes.php <filter>
 */

$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['REQUEST_URI'] = '/';
require_once '/var/www/html/wp-load.php';

do_action('rest_api_init');

$server = rest_get_server();
$routes = $server->get_routes();
$filter = isset($argv[1]) ? $argv[1] : null;

$count = 0;
foreach ($routes as $route => $handlers) {
    if ($filter && stripos($route, $filter) === false) {
        continue;
    }
    $methods = [];
    foreach ($handlers as $handler) {
        if (isset($handler['methods'])) {
            $methods = array_merge($methods, array_keys($handler['methods']));
        }
    }
    $methods = array_unique($methods);
    printf("%-12s %s\n", implode(',', $methods), $route);
    $count++;
}

echo "\n$count route(s)" . ($filter ? " matching '$filter'" : " total") . "\n";
