<?php

// Unauthenticated REST pre-dispatch handler rewriting a define() inside a
// PHP config file with raw request data — no quote escaping before the write.
function hook_rest_pre_dispatch($result, $server, $request) {
    $config_file = WP_PLUGIN_DIR . '/myplugin/config.php';
    $siteurl = $request['myplugin_siteurl'];
    $file_content = file_get_contents($config_file);
    $file_content = preg_replace("/(define\('MYPLUGIN_SITE_URL'\,\s\')(.*)(\'\)\;)/", "$1$siteurl$3", $file_content);
    // ruleid: claude.php.wordpress.rce.request-data-to-php-config-write
    file_put_contents($config_file, $file_content);
    return $result;
}

// AJAX handler building a settings.php constants file from raw POST data
// via fwrite() onto an fopen()'d handle.
function save_settings_unsafe() {
    $license = $_POST['license_key'];
    $settings_handle = fopen(plugin_dir_path(__FILE__) . 'settings.php', 'w');
    $body = "<?php\ndefine('MYPLUGIN_LICENSE', '" . $license . "');\n";
    // ruleid: claude.php.wordpress.rce.request-data-to-php-config-write
    fwrite($settings_handle, $body);
}

// Fixed variant: value is escaped with addslashes() before it is spliced
// into the generated PHP config file.
function save_settings_fixed() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Forbidden', 403);
    }
    $config_file = plugin_dir_path(__FILE__) . 'config.php';
    $siteurl = addslashes((string) sanitize_text_field($_POST['myplugin_siteurl'] ?? ''));
    $body = "<?php\ndefine('MYPLUGIN_SITE_URL', '" . $siteurl . "');\n";
    // ok: claude.php.wordpress.rce.request-data-to-php-config-write
    file_put_contents($config_file, $body);
}

// Fixed variant: value is passed through var_export() so it is emitted as
// a properly quoted/escaped PHP literal.
function save_license_fixed() {
    check_ajax_referer('myplugin_save', '_ajax_nonce');
    $license = var_export((string) $_POST['license_key'], true);
    $body = "<?php\ndefine('MYPLUGIN_LICENSE', " . $license . ");\n";
    // ok: claude.php.wordpress.rce.request-data-to-php-config-write
    file_put_contents(plugin_dir_path(__FILE__) . 'license-config.php', $body);
}

// Ordinary DB-read value written to a non-config export file — sink
// destination name doesn't match the config/settings/constants heuristic.
function export_report() {
    global $wpdb;
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}myplugin_log");
    $csv = print_r($rows, true);
    // ok: claude.php.wordpress.rce.request-data-to-php-config-write
    file_put_contents(plugin_dir_path(__FILE__) . 'export-report.csv', $csv);
}

// Unauthenticated AJAX handler (nopriv) writing raw POST content into a
// heredoc-wrapped .php cache file via the WP_Filesystem wrapper — the
// closing heredoc identifier is never rejected, so a line matching it in
// the POST body breaks out into arbitrary PHP that runs on next include or
// direct request of the cache file (CVE-2025-12813 shape).
function hcpcldr_save_cache_unsafe() {
    global $wp_filesystem;
    WP_Filesystem();
    $fileid = $_POST['fileid'];
    $contents = str_replace(array('\"', '\\\''), array('"', '\''), $_POST['contents']);
    $contents = "<?php\n\$contents=<<<HERE\n" . $contents . "\nHERE;\n?>";
    $cache_file = plugin_dir_path(__FILE__) . 'cache/hcpcldr_cache_' . $fileid . '.php';
    // ruleid: claude.php.wordpress.rce.request-data-to-php-config-write
    $wp_filesystem->put_contents($cache_file, $contents);
}

// Fixed variant: value is escaped with addslashes() before being spliced
// into the heredoc body written through the same WP_Filesystem sink.
function hcpcldr_save_cache_fixed() {
    global $wp_filesystem;
    WP_Filesystem();
    check_ajax_referer('hcpcldr_save', 'nonce');
    $fileid = sanitize_key($_POST['fileid']);
    $contents = addslashes((string) $_POST['contents']);
    $contents = "<?php\n\$contents=<<<HERE\n" . $contents . "\nHERE;\n?>";
    $cache_file = plugin_dir_path(__FILE__) . 'cache/hcpcldr_cache_' . $fileid . '.php';
    // ok: claude.php.wordpress.rce.request-data-to-php-config-write
    $wp_filesystem->put_contents($cache_file, $contents);
}
