<?php
// Test file for request-param-filename-concat-no-int-cast rule
// Seeded by CVE-2024-10585 (InfiniteWP Client <= 1.13.0 debug-chart/index.php)

// ruleid: claude.php.wordpress.file.request-param-filename-concat-no-int-cast
$iwp_multicall_hisID = $_GET['historyID'];
$current_dir = dirname(__FILE__) . '/backups';
$memoryUsageLog = 'DE_clMemoryUsage.' . $iwp_multicall_hisID . '.txt';
$file = $current_dir . '/' . $memoryUsageLog;
new DebugChartReader($file);

function bad_post_variant() {
    // ruleid: claude.php.wordpress.file.request-param-filename-concat-no-int-cast
    $reportId = $_POST['report_id'];
    $misc = 'unrelated';
    $logName = 'report-' . $reportId . '.csv';
    read_report_log($logName);
}

function good_fixed_abs_int_cast() {
    $iwp_multicall_hisID = $_GET['historyID'];
    $iwp_multicall_hisID = abs( (int) $iwp_multicall_hisID );
    // ok: claude.php.wordpress.file.request-param-filename-concat-no-int-cast
    $memoryUsageLog = 'DE_clMemoryUsage.' . $iwp_multicall_hisID . '.txt';
    $file = dirname(__FILE__) . '/' . $memoryUsageLog;
    new DebugChartReader($file);
}

function good_direct_absint_cast() {
    $reportId = absint($_GET['report_id']);
    // ok: claude.php.wordpress.file.request-param-filename-concat-no-int-cast
    $logName = 'report-' . $reportId . '.csv';
    read_report_log($logName);
}

function good_no_request_source() {
    $count = get_option('widget_count');
    // ok: claude.php.wordpress.file.request-param-filename-concat-no-int-cast
    $cacheKey = 'widget-cache-' . $count . '.tmp';
    return $cacheKey;
}
