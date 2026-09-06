<?php
/**
 * check-environment.php — Pre-flight validation environment check.
 *
 * Reports: PHP extensions, memory_limit, WP_DEBUG, permalink structure,
 * active plugins, plugin health via HTTP self-test, debug.log errors.
 *
 * Usage: docker compose exec -T wordpress php /tmp/check-environment.php [plugin-slug]
 *
 * Pass the plugin slug as $argv[1] to run a targeted HTTP health check
 * that verifies the plugin is actually functional (not just DB-active).
 */

$plugin_slug = isset($argv[1]) ? $argv[1] : null;
$warnings = 0;

echo "=== Environment Pre-flight Check ===\n\n";

// ── PHP extensions ──────────────────────────────────────────────────────────
$required = ['curl', 'dom', 'json', 'mbstring', 'mysqli', 'pdo_mysql', 'gd', 'xml', 'zip'];
$missing = [];
foreach ($required as $ext) {
    if (!extension_loaded($ext)) { $missing[] = $ext; }
}
if ($missing) {
    echo "[PHP] extensions: *** WARNING: missing " . implode(', ', $missing) . "\n";
    $warnings++;
} else {
    echo "[PHP] extensions: all required loaded (" . implode(', ', $required) . ")\n";
}
$extra = ['intl', 'soap', 'exif', 'imagick'];
$loaded_extra = array_filter($extra, 'extension_loaded');
if ($loaded_extra) {
    echo "[PHP] extras:     " . implode(', ', $loaded_extra) . "\n";
}

// PHP memory
$mem = ini_get('memory_limit');
$mem_mb = (int) $mem;
if ($mem_mb < 256 && $mem_mb > 0) {
    echo "[PHP] memory_limit: $mem *** WARNING: < 256M\n";
    $warnings++;
} else {
    echo "[PHP] memory_limit: $mem\n";
}

// ── WP bootstrap ────────────────────────────────────────────────────────────
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['REQUEST_URI'] = '/';
require_once '/var/www/html/wp-load.php';

echo "\n";
echo "[WP]  WP_DEBUG: " . (defined('WP_DEBUG') && WP_DEBUG ? 'ON' : 'OFF') . "\n";
echo "[WP]  WP_DEBUG_LOG: " . (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG ? 'ON' : 'OFF') . "\n";

// debug.log — check existence, size, and dump recent errors
$log = WP_CONTENT_DIR . '/debug.log';
if (file_exists($log)) {
    $size = filesize($log);
    $writable = is_writable($log) ? 'yes' : '*** NO';
    echo "[WP]  debug.log: exists ($size bytes, writable: $writable)\n";
    if ($size > 0) {
        $lines = file($log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $errors = array_filter($lines, function($l) {
            return stripos($l, 'Fatal') !== false
                || stripos($l, 'Error') !== false
                || stripos($l, 'Warning') !== false;
        });
        // Skip Xdebug noise
        $errors = array_filter($errors, function($l) {
            return stripos($l, 'Xdebug') === false;
        });
        if ($errors) {
            $errors = array_slice($errors, -10);
            echo "[WP]  debug.log errors (last " . count($errors) . "):\n";
            foreach ($errors as $e) {
                echo "      $e\n";
            }
            $warnings++;
        }
    }
} else {
    echo "[WP]  debug.log: *** MISSING\n";
    $warnings++;
}

// Permalinks
$structure = get_option('permalink_structure');
if (empty($structure)) {
    echo "[WP]  permalinks: (plain) *** WARNING: REST /wp-json/ will 404\n";
    $warnings++;
} else {
    echo "[WP]  permalinks: $structure\n";
}

// Active plugins
$active = get_option('active_plugins', []);
echo "[WP]  active plugins: " . count($active) . "\n";
foreach ($active as $p) {
    echo "      - $p\n";
}

// ── HTTP self-test (the authoritative check) ────────────────────────────────
echo "\n--- HTTP Self-Test (authoritative) ---\n";

// Inside the container Apache listens on port 80. The siteurl may say port 8000
// (the Docker-published port), which isn't reachable from inside. Always self-test
// on 127.0.0.1:80 with the Host header matching siteurl so WordPress doesn't redirect.
$site_url = get_option('siteurl');
$site_host_header = parse_url($site_url, PHP_URL_HOST) ?: 'localhost';
$site_port = parse_url($site_url, PHP_URL_PORT);
if ($site_port) { $site_host_header .= ':' . $site_port; }

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => 'http://127.0.0.1/',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HEADER => false,
    CURLOPT_HTTPHEADER => ["Host: $site_host_header"],
]);
$body = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "[HTTP] GET / → $code (" . ($body ? strlen($body) . " bytes" : "empty") . ")\n";
if ($code < 200 || $code >= 400) {
    echo "[HTTP] *** WARNING: homepage not serving correctly\n";
    $warnings++;
}

// REST API namespace check via HTTP
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => 'http://127.0.0.1/wp-json/',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTPHEADER => ["Host: $site_host_header"],
]);
$api_body = curl_exec($ch);
$api_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$namespaces = [];
if ($api_code === 200 && $api_body) {
    $data = json_decode($api_body, true);
    $namespaces = isset($data['namespaces']) ? $data['namespaces'] : [];
}
echo "[HTTP] GET /wp-json/ → $api_code, " . count($namespaces) . " namespace(s)\n";
if ($namespaces) {
    foreach ($namespaces as $ns) {
        echo "       - $ns\n";
    }
}

// ── Plugin-specific health check ────────────────────────────────────────────
if ($plugin_slug) {
    echo "\n--- Plugin Health: $plugin_slug ---\n";

    // Check if plugin is in active_plugins
    $is_db_active = false;
    foreach ($active as $p) {
        if (strpos($p, $plugin_slug . '/') === 0 || $p === $plugin_slug) {
            $is_db_active = true;
            break;
        }
    }
    echo "[PLUG] DB active: " . ($is_db_active ? 'YES' : '*** NO') . "\n";
    if (!$is_db_active) { $warnings++; }

    // Check if plugin scripts/styles appear on homepage
    if ($body) {
        $slug_in_html = stripos($body, $plugin_slug) !== false;
        echo "[PLUG] Script/style on homepage: " . ($slug_in_html ? 'YES' : 'no (may be normal for admin-only plugins)') . "\n";
    }

    // Check if plugin has REST routes registered via HTTP
    // Exclude standard WP namespaces, then list all non-WP namespaces so the
    // operator can see what the plugin registered (namespace often differs from slug)
    $wp_core_ns = ['oembed/1.0', 'wp/v2', 'wp-site-health/v1', 'wp-block-editor/v1', 'wp-abilities/v1'];
    $third_party_ns = array_diff($namespaces, $wp_core_ns);
    if ($third_party_ns) {
        echo "[PLUG] Non-core REST namespaces (HTTP): " . implode(', ', $third_party_ns) . "\n";
    } else {
        echo "[PLUG] Non-core REST namespaces (HTTP): none (plugin may use AJAX only)\n";
    }

    // Check for plugin-specific errors in debug.log
    if (file_exists($log) && filesize($log) > 0) {
        $all_lines = file($log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $plugin_errors = array_filter($all_lines, function($l) use ($plugin_slug) {
            return (stripos($l, $plugin_slug) !== false || stripos($l, str_replace('-', '_', $plugin_slug)) !== false)
                && stripos($l, 'Xdebug') === false;
        });
        if ($plugin_errors) {
            echo "[PLUG] *** Plugin errors in debug.log:\n";
            foreach (array_slice($plugin_errors, -5) as $e) {
                echo "       $e\n";
            }
            $warnings++;
        } else {
            echo "[PLUG] debug.log: no plugin-specific errors\n";
        }
    }

    // Check plugin DB tables exist (common prefix patterns)
    global $wpdb;
    $short_slug = str_replace('-', '_', $plugin_slug);
    $tables = $wpdb->get_col("SHOW TABLES LIKE '%{$short_slug}%'");
    if ($tables) {
        echo "[PLUG] DB tables: " . count($tables) . " (" . implode(', ', array_slice($tables, 0, 5)) . (count($tables) > 5 ? '...' : '') . ")\n";
    } else {
        echo "[PLUG] DB tables: none matching '%{$short_slug}%' (may use wp_options only)\n";
    }
}

// ── Summary ─────────────────────────────────────────────────────────────────
echo "\n[ENV] WordPress: " . get_bloginfo('version') . "\n";
echo "[ENV] PHP: " . PHP_VERSION . "\n";
echo "[ENV] Site URL: " . get_option('siteurl') . "\n";

if ($warnings > 0) {
    echo "\n*** $warnings WARNING(S) — review above before proceeding ***\n";
} else {
    echo "\n=== Pre-flight PASSED — no warnings ===\n";
}
