<?php

class Url
{
    public static function getParam($url, $param)
    {
        $parsed = wp_parse_url($url);
        if (empty($parsed['query'])) return null;
        parse_str($parsed['query'], $params);
        return $params[$param] ?? null;
    }
}

// Real-world shape adapted from a confirmed unauthenticated stored XSS: a
// referral-source parser builds a lookup array of tracking-parameter values
// pulled from the current page URL, then stores the raw value directly as a
// display "name" when the matched channel domain is a wildcard.
class ReferralsParser
{
    public function parse($referrerUrl, $pageUrl)
    {
        $channels = [];

        $sourceParams = array_filter([
            'utm_source' => Url::getParam($pageUrl, 'utm_source'),
            'source'     => Url::getParam($pageUrl, 'source'),
            'ref'        => Url::getParam($pageUrl, 'ref'),
        ]);

        foreach ($sourceParams as $key => $value) {
            $currentChannel = ['name' => 'Direct', 'identifier' => 'direct'];

            if (empty($channels[$key])) {
                $channels[$key] = $currentChannel;

                // ruleid: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
                $channels[$key]['name'] = $value;
            }
        }

        return $channels;
    }
}

// A simpler single-function variant: a UTM parameter read directly from the
// request and persisted straight to an option without an intervening array.
function wps_store_last_referral()
{
    // ruleid: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
    update_option('last_campaign', $_GET['utm_campaign']);
}

// ok: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
class ReferralsParserSafe
{
    public function parse($referrerUrl, $pageUrl)
    {
        $channels = [];

        $sourceParams = array_filter([
            'utm_source' => Url::getParam($pageUrl, 'utm_source'),
        ]);

        foreach ($sourceParams as $key => $value) {
            $currentChannel = ['name' => 'Direct', 'identifier' => 'direct'];

            if (empty($channels[$key])) {
                $channels[$key] = $currentChannel;
                $channels[$key]['name'] = sanitize_text_field($value);
            }
        }

        return $channels;
    }
}

// ok: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
function wps_read_visitor_row($id)
{
    global $wpdb;

    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}visitors WHERE ID = %d", $id));

    return $row;
}

// Real-world shape adapted from a confirmed unauthenticated stored XSS: an
// order-enrichment helper reads the first-party attribution cookie/session
// value directly (no sanitizer) as the fallback when the request parameter
// is absent, then persists the combined value into order meta rendered
// later on the admin order screen.
function wps_build_order_attribution_meta()
{
    $landing = $source = '';

    if (isset($_COOKIE['wps_landing_page']) || isset($_SESSION['LandingPage'])) {
        $landing = $_COOKIE['wps_landing_page'] ?? $_SESSION['LandingPage'];
    }
    if (isset($_COOKIE['wpsTrafficSource']) || isset($_SESSION['TrafficSource'])) {
        $source = $_COOKIE['wpsTrafficSource'] ?? $_SESSION['TrafficSource'];
    }

    $orderMeta = [];
    // ruleid: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
    $orderMeta['wps_landing'] = isset($_REQUEST['wps_landing']) ? sanitize_text_field($_REQUEST['wps_landing']) : $landing;
    // ruleid: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
    $orderMeta['wps_source'] = isset($_REQUEST['wps_source']) ? sanitize_text_field($_REQUEST['wps_source']) : $source;

    // ruleid: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
    update_post_meta(get_the_ID(), 'wps_enrich_data', $orderMeta);

    return $orderMeta;
}

// ok: claude.php.wordpress.xss.tracking-param-store-no-sanitizer
// Fixed shape: the cookie/session fallback is now unconditionally passed
// through sanitize_text_field() regardless of which branch supplied it.
function wps_build_order_attribution_meta_safe()
{
    $landing = $_SESSION['LandingPage'] ?? $_COOKIE['wps_landing_page'];
    $landing = sanitize_text_field($landing ?? '');

    $source = $_SESSION['TrafficSource'] ?? $_COOKIE['wpsTrafficSource'];
    $source = sanitize_text_field($source ?? '');

    $orderMeta = [];
    $orderMeta['wps_landing'] = isset($_REQUEST['wps_landing']) ? sanitize_text_field($_REQUEST['wps_landing']) : $landing;
    $orderMeta['wps_source'] = isset($_REQUEST['wps_source']) ? sanitize_text_field($_REQUEST['wps_source']) : $source;

    update_post_meta(get_the_ID(), 'wps_enrich_data', $orderMeta);

    return $orderMeta;
}
